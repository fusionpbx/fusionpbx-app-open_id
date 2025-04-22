<?php

/*
 * FusionPBX
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FusionPBX
 *
 * The Initial Developer of the Original Code is
 * Mark J Crane <markjcrane@fusionpbx.com>
 * Portions created by the Initial Developer are Copyright (C) 2008-2025
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Mark J Crane <markjcrane@fusionpbx.com>
 * Tim Fry <tim@fusionpbx.com>
 */

/**
 * Description of open_id
 *
 * @author Tim Fry <tim@fusionpbx.com>
 * @requires $_SESSION
 */
class open_id_okta implements open_id_authenticator {

	/**
	 * The authentication URL for the OpenID provider
	 * @var string $metadata_uri
	 */
	private $metadata_uri;

	/**
	 * Client ID from provider
	 * @var string
	 */
	private $client_id;

	/**
	 * Client secret from provider
	 * @var string
	 */
	private $client_secret;

	/**
	 * Redirect URI that must match provider
	 * @var string
	 */
	private $redirect_uri;

	/**
	 * Login Destination
	 * @var string
	 */
	private $login_destination;
	//
	// Backwards compatibility
	//
	public $domain_name;
	public $domain_uuid;

	/**
	 * Most recent curl error
	 * @var string
	 */
	public $curl_error;
	private $table_field;
	private $okta_field;
	private $suppress_errors;

	/**
	 * Create an authentication object for OpenID Connect
	 * @param settings $settings settings object
	 * @depends $_SESSION
	 */
	public function __construct() {
		global $settings;

		//
		// Ensure we have a valid settings object
		//
		if (!($settings instanceof settings)) {
			$settings = new settings([
				'database' => database::new(),
				'domain_uuid' => $_SESSION['domain_uuid'] ?? '',
			]);
		}

		// Set the suppress errors with a default of true to avoid UI interruption
		$this->suppress_errors = $settings->get('open_id', 'suppress_errors', true);

		//
		// Get the client ID and secret
		//
		$this->client_id = $settings->get('open_id', 'okta_client_id');
		$this->client_secret = $settings->get('open_id', 'okta_client_secret');
		$this->redirect_uri = $settings->get('open_id', 'okta_redirect_uri');	//, $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . '/app/open_id/open_id.php'

		//
		// Replace the {$domain_name} placeholder for user
		//
		if (str_contains($this->redirect_uri, '{$domain_name}')) {
			$this->redirect_uri = str_replace('{$domain_name}', $_SERVER['HTTP_HOST'], $this->redirect_uri);
		}

		//
		// Replace the {$plugin} placeholder for user
		//
		if (str_contains($this->redirect_uri, '{$plugin}')) {
			$this->redirect_uri = str_replace('{$plugin}', self::class, $this->redirect_uri);
		}

		// Get the field mapping for the okta email address to the user email address or username field in v_users table
		$mapping = $settings->get('open_id', 'okta_username_mapping');

		// When errors are allowed and the field mapping is empty throw an error
		if (!$this->suppress_errors && empty($mapping)) throw new \InvalidArgumentException('okta_username_mapping must not be empty');

		// When errors are allowed and the mapping does not have an equals (=) sign throw an error
		if (!$this->suppress_errors && !str_contains($mapping, '=')) throw new \InvalidArgumentException('okta_username_mapping must be in the form of okta_oidc_field=user_column');

		// Map the OKTA OpenID Connect (OIDC) field to the user table field to validate the user exists
		[$okta_field, $table_field] = explode('=', $mapping, 2);

		// Trim the whitespace for field names and store in the object
		$this->okta_field = trim($okta_field);
		$this->table_field = trim($table_field);

		// Test that both fields for lookup are not empty
		if (!$this->suppress_errors && empty($this->okta_field)) throw new \InvalidArgumentException('OKTA OpenID Connect field must not be emtpy in okta_oidc_field default settings');
		if (!$this->suppress_errors && empty($this->table_field)) throw new \InvalidArgumentException('Users table field must not be emtpy in okta_oidc_field default settings');

		// Test the 'table_field' column exists in the v_users table
		if (!$this->suppress_errors && !empty($this->table_field) && !$settings->database()->column_exists(database::TABLE_PREFIX . 'users', $this->table_field)) throw new \InvalidArgumentException("Users table field $this->table_field does not exist in the users table");

		//
		// Set up the URL for openID
		//
		$metadata_domain = $settings->get('open_id', 'okta_metadata_domain');

		//
		// We must use a secure protocol to connect
		//
		if (!str_starts_with($metadata_domain, 'https://')) {
			$metadata_domain = 'https://' . $metadata_domain;
		}
		if (!str_ends_with($metadata_domain, '/')) {
			$metadata_domain .= '/';
		}

		//
		// Get the server name
		//
		$metadata_server = $settings->get('open_id', 'okta_metadata_server', '');
		if (!empty($metadata_server) && !str_starts_with($metadata_server, '/')) {
			$metadata_server = '/' . $metadata_server;
		}

		//
		// Complete the URI
		//
		$this->metadata_uri = $metadata_domain . 'oauth2' . $metadata_server . '/.well-known/oauth-authorization-server';

		//
		// Get the login destination using /core/dashboard as default
		//
		$this->login_destination = $settings->get('login', 'destination', '/core/dashboard');

		//
		// Error messages reported by cURL requests
		//
		$this->curl_error = '';
	}

	/**
	 * Build the authentication URL.
	 *
	 * Constructs the URL with required OpenID parameters.
	 *
	 * @return string The built authentication URL.
	 */
	private function build_params() {
		$code_challenge = self::encode_string_to_url_base64(hash('sha256', $_SESSION['okta_code_verifier'], true));
		$params = [
			'response_type' => 'code',
			'client_id' => $this->client_id,
			'redirect_uri' => $this->redirect_uri,
			'state' => $_SESSION['okta_state'],
			'scope' => 'openid profile',
			'code_challenge' => $code_challenge,
			'code_challenge_method' => 'S256',
		];
		return http_build_query($params);
	}

	/**
	 * Send a POST request to a server using the curl extension
	 * @param string $url
	 * @param array $params
	 * @param string $curl_error
	 * @return array
	 */
	private static function post(string $url, array $params = [], string &$curl_error = ''): array {
		$json_array = [];

		// Standard installs have this so it should never trigger
		if (!function_exists('curl_init')) {
			throw new \Exception('Missing curl extension');
		}

		// Get the curl handle
		$curl = curl_init($url);

		// Set up the options for the post fields and ensure a return
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		if (count($params) > 0) {
			curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
		}

		// Send the POST and get the response
		$response = curl_exec($curl);
		if (!empty($response)) {
			$json_array = json_decode($response, true);
		} else {
			// Invalid response
			$curl_error = curl_error($curl);
		}

		// Close the connection
		curl_close($curl);

		// Return the decoded array
		if (!empty($json_array))
			return $json_array;

		// Return empty array
		return [];
	}

	/**
	 * Encodes a string to base64 that is compatible with for use in a URL
	 * @param string $string
	 * @return string
	 */
	private static function encode_string_to_url_base64(string $string): string {
		return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
	}

	public static function logout() {
		global $settings;

		//
		// Ensure we have a valid settings object
		//
		if (!($settings instanceof settings)) {
			$settings = new settings([
				'database' => database::new(),
				'domain_uuid' => $_SESSION['domain_uuid'] ?? '',
				'user_uuid' => $_SESSION['user_uuid'] ?? '',
			]);
		}

		//
		// Set up the URL for OKTA OpenID
		//
		$metadata_domain = $settings->get('open_id', 'okta_metadata_domain');

		//
		// We must use a secure protocol to connect
		//
		if (!str_starts_with($metadata_domain, 'https://')) {
			$metadata_domain = 'https://' . $metadata_domain;
		}
		if (!str_ends_with($metadata_domain, '/')) {
			$metadata_domain .= '/';
		}

		//
		// Get the server name
		//
		$metadata_server = $settings->get('open_id', 'okta_metadata_server', '');
		if (!str_starts_with($metadata_server, '/')) {
			$metadata_server = '/' . $metadata_server;
		}

		//
		// Complete the logout URI variables
		//
		$redirect_uri = urlencode($settings->get('open_id', 'okta_redirect_uri', $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . '/login.php'));
		$logout_url = $_SESSION['okta_end_session'] ?? null;
		$token = $_SESSION['okta_session_token'] ?? null;

		//
		// Short-circuit the logout process so we can de-authenticate on the OpenID server
		//
		if ($token !== null) {
			session_unset();
			session_destroy();
			// Set a post_logout_redirect parameter
			$redirect = $logout_url ?? "&post_logout_redirect_uri={$redirect_uri}";
			// Redirect user
			header("Location: {$logout_url}?id_token_hint={$token}{$redirect}");
			exit();
		}

		//
		// Clean up session data if no token
		//
		unset($_SESSION['okta_access_token']);
		unset($_SESSION['okta_session_token']);
		unset($_SESSION['okta_end_session']);
		unset($_SESSION['okta_state']);
		unset($_SESSION['okta_code_verifier']);

		//
		// Return back to logout process
		//
		return;
	}

	/**
	 * Authenticate the user via OKTA OpenID.
	 *
	 * This method initiates the OpenID authentication process if no response is
	 * detected. When the OpenID provider returns the authentication response,
	 * it validates the response.
	 *
	 * @return array Returns user data associative array if authentication is successful, or an empty array otherwise.
	 */
	public function authenticate(): array {
		// Set default return value
		$result = [];

		// First we need to get the authentication metadata from the openid server
		$metadata = self::post($this->metadata_uri, [], $this->curl_error);

		if (!isset($_GET['code'])) {
			// Set the state and code_verifier
			$_SESSION['okta_state'] = bin2hex(random_bytes(5));
			$_SESSION['okta_code_verifier'] = bin2hex(random_bytes(50));

			// Send the authentication request to the authorization server
			$authorize_url = $metadata['authorization_endpoint'] . '?' . $this->build_params();

			// Redirect to OKTA Authorization Screen
			header('Location: ' . $authorize_url);
			exit();
		} else {

			// State must match
			if ($_SESSION['okta_state'] != $_GET['state']) {
				die('Authorization server returned an invalid state parameter');
			}

			// Server can respond with an error
			if (isset($_GET['error'])) {
				die('Authorization server returned an error: ' . htmlspecialchars($_GET['error']));
			}

			// Get the initial response from the server
			$access_token = self::post($metadata['token_endpoint'], [
				'grant_type' => 'authorization_code',
				'code' => $_GET['code'],
				'redirect_uri' => $this->redirect_uri,
				'client_id' => $this->client_id,
				'client_secret' => $this->client_secret,
				'code_verifier' => $_SESSION['okta_code_verifier'],
					], $this->curl_error);

			// We should have an access token
			if (empty($access_token['access_token'])) {
				throw new \Exception('Error fetching access token');
			}

			// Something else went wrong
			if (!empty($access_token['error'])) {
				throw new \Exception($access_token['error_description']);
			}

			// Using the initial authority token we can request the OpenID user information
			$id_token = self::post($metadata['introspection_endpoint'], [
				'client_id' => $this->client_id,
				'client_secret' => $this->client_secret,
				'token' => $access_token['access_token']
					], $this->curl_error);

			// Something else went wrong
			if (!empty($id_token['error'])) {
				throw new \Exception($id_token['error_description']);
			}

			// The token should now have an active boolean true/false
			if ($id_token['active']) {
				global $database;
				$sql  = 'select user_uuid, username, u.domain_uuid, d.domain_name';
				$sql .= ' from v_users u';
				$sql .=	' left outer join v_domains d on d.domain_uuid = u.domain_uuid';
				$sql .= " where $this->table_field = :$this->table_field";
				$sql .= " and user_enabled = 'true'";
				$sql .= " limit 1";

				//
				// Use the field from okta to find user in the v_users table
				//
				$parameters = [];
				$parameters[$this->table_field] = $id_token[$this->okta_field];

				//get the user array from the local database
				$user = $database->select($sql, $parameters, 'row');

				//couldn't find a matching user in the database
				if (empty($user)) {
					return $result;
				}

				//save necessary tokens so we can logout
				$_SESSION['okta_access_token']  = $access_token['access_token'];
				$_SESSION['okta_session_token'] = $access_token['id_token'];
				$_SESSION['okta_end_session']   = $metadata['end_session_endpoint'];

				//set up the response from the plugin
				$result["plugin"] = self::class;
				$result["domain_uuid"] = $user['domain_uuid'];
				$result["domain_name"] = $user['domain_name'];
				$result["username"] = $user['username'];
				$result["user_uuid"] = $user['user_uuid'];

				$result["user_email"] = $id_token['username'];
				$result["authorized"] = true;

				//
				// Remove the failed login message
				//
				$_SESSION['authorized'] = true;
			}
			// Return the login result
			return $result;
		}
	}

	public static function get_banner_image(): string {
		return "<div class=''"
				. " style='display: inline-block;"
				. " border: 2px solid #ccc;"
				. " border-radius: 4px;"
				. " padding: 8px 22px;"
				. " background-color: #fff;"
				. " color: #444;"
				. " font-family: Arial, sans-serif;"
				. " text-decoration: none;"
				. " cursor: pointer;'>"
					. "Sign-in with OKTA"
				. "</div>"
		;
	}
}

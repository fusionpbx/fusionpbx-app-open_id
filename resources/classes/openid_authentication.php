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
class openid_authentication implements logout_event {

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
				'user_uuid' => $_SESSION['user_uuid'] ?? '',
			]);
		}

		//
		// Set up the URL for openID
		//
		$metadata_domain = $settings->get('authentication', 'openid_metadata_domain');

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
		$metadata_server = $settings->get('authentication', 'openid_metadata_server', '');
		if (!empty($metadata_server) && !str_starts_with($metadata_server, '/')) {
			$metadata_server = '/' . $metadata_server;
		}

		//
		// Complete the URI
		//
		$this->metadata_uri = $metadata_domain . 'oauth2' . $metadata_server . '/.well-known/oauth-authorization-server';

		//
		// Get the client ID and secret
		//
		$this->client_id = $settings->get('authentication', 'openid_client_id', '');
		$this->client_secret = $settings->get('authentication', 'openid_client_secret', '');

		//
		// Get the login destination using /core/dashboard as default
		//
		$this->login_destination = $settings->get('login', 'destination', '/core/dashboard');

		//
		// Redirect URI must match the openID setting
		//
		$this->redirect_uri = $settings->get('authentication', 'openid_redirect_uri', $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . '/login.php');

		//
		// Error messages reported by cURL requests
		//
		$this->curl_error = '';
	}

	/**
	 * Authenticate the user via OpenID.
	 *
	 * This method initiates the OpenID authentication process if no response is
	 * detected. When the OpenID provider returns the authentication response,
	 * it validates the response.
	 *
	 * @return mixed Returns user data array if authentication is successful, false otherwise.
	 */
	public function openid() {
		//
		// First we need to get the authentication metadata from the openid server
		//
		$metadata = self::post($this->metadata_uri, [], $this->curl_error);

		if (!isset($_GET['code'])) {
			//
			// Set the state and code_verifier
			//
			$_SESSION['openid_state'] = bin2hex(random_bytes(5));
			$_SESSION['openid_code_verifier'] = bin2hex(random_bytes(50));

			//
			// Send the authentication request to the authorization server
			//
			$authorize_url = $metadata['authorization_endpoint'] . '?' . $this->build_params();

			//
			// Not logged in yet
			//
			header('Location: ' . $authorize_url);
			exit();
		} else {

			// State must match
			if ($_SESSION['openid_state'] != $_GET['state']) {
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
				'code_verifier' => $_SESSION['openid_code_verifier'],
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
				$sql = "select user_uuid, username, domain_uuid from v_users where user_email = :user_email and user_enabled = 'true' limit 1";
				$parameters = [];

				//username is the email address of user
				$parameters['user_email'] = $id_token['username'];

				//get the user array from the local database
				$user = $database->select($sql, $parameters, 'row');

				//couldn't find a matching user in the database
				if (empty($user)) {
					return false;
				}
				$result = [];

				//save necessary tokens so we can logout
				$_SESSION['openid_access_token'] = $access_token['access_token'];
				$_SESSION['openid_session_token'] = $access_token['id_token'];
				$_SESSION['openid_end_session'] = $metadata['end_session_endpoint'];
				//set up the response from the plugin
				$result["plugin"] = "openid";
				$result["domain_name"] = $user['domain_name'];
				$result["username"] = $user['username'];
				$result["user_uuid"] = $user['user_uuid'];
				$result["domain_uuid"] = $user['domain_uuid'];
				$result["user_email"] = $id_token['username'];
				$result["authorized"] = $id_token['active'];
				//return the array
				return $result;
			}
			// The token was false so return false
			return false;
		}
	}

	/**
	 * Build the authentication URL.
	 *
	 * Constructs the URL with required OpenID parameters.
	 *
	 * @return string The built authentication URL.
	 */
	private function build_params() {
		$code_challenge = self::encode_string_to_url_base64(hash('sha256', $_SESSION['openid_code_verifier'], true));
		$params = [
			'response_type' => 'code',
			'client_id' => $this->client_id,
			'redirect_uri' => $this->redirect_uri,
			'state' => $_SESSION['openid_state'],
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
		// Ensure openid is enabled before trying to logout to authentication server
		//
		$methods = $settings->get('authentication', 'methods', []);
		if (!in_array(basename(__FILE__, '.php'), $methods)) {
			return false;
		}

		//
		// Set up the URL for openID
		//
		$metadata_domain = $settings->get('authentication', 'openid_metadata_domain');

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
		$metadata_server = $settings->get('authentication', 'openid_metadata_server', '');
		if (!str_starts_with($metadata_server, '/')) {
			$metadata_server = '/' . $metadata_server;
		}

		//
		// Complete the logout URI variables
		//
		$redirect_uri = urlencode($settings->get('authentication', 'openid_redirect_uri', $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . '/login.php'));
		$logout_url = $_SESSION['openid_end_session'] ?? null;
		$token = $_SESSION['openid_session_token'] ?? null;

		//
		// Short-circuit the logout process so we can de-authenticate with the OpenID server
		//
		if ($token !== null) {
			session_unset();
			session_destroy();
			// Set a post_logout_redirect parameter
			$redirect = ($logout_url === null) ? '' : "&post_logout_redirect_uri={$redirect_uri}";
			// Redirect user
			header("Location: {$logout_url}?id_token_hint={$token}{$redirect}");
			exit();
		}
		return;
	}

}

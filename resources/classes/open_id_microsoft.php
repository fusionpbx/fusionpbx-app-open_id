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
 *
 * Microsoft (Entra ID / Azure AD) OpenID Connect authenticator.
 * Modeled on open_id_google. Microsoft is a standard OIDC provider using
 * discovery + authorization-code flow, so the flow mirrors the Google class.
 */

/**
 * Authenticate FusionPBX users against Microsoft Entra ID (Azure AD).
 *
 * @author Tim Fry <tim@fusionpbx.com>
 * @requires $_SESSION
 */
class open_id_microsoft implements open_id_authenticator {

	//
	// OpenID Connect State Variables
	//

	protected $client_id;
	protected $client_secret;
	protected $redirect_uri;
	protected $scope;
	protected $state;
	protected $discovery_url;
	protected $auth_endpoint;
	protected $token_endpoint;
	protected $userinfo_endpoint;
	protected $end_session_endpoint;

	/**
	 * When true, no errors will be thrown. Helpful while configuring the client.
	 * @var bool
	 */
	protected $suppress_errors;

	/**
	 * OIDC claim name used to locate the local user (e.g. preferred_username)
	 * @var string
	 */
	protected $microsoft_field;

	/**
	 * v_users table column the claim maps to (e.g. user_email)
	 * @var string
	 */
	protected $table_field;

	/**
	 * Set up the Microsoft URL parameters and object variables.
	 *
	 * @param string $scope Space-separated scopes (default: "openid email profile").
	 */
	public function __construct(string $scope = "openid email profile") {
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

		// Set the suppress errors with a default of true to avoid UI interruption
		$this->suppress_errors = $settings->get('open_id', 'suppress_errors', true);

		// Set up the Entra app registration settings
		$this->client_id = $settings->get('open_id', 'microsoft_client_id');
		$this->client_secret = $settings->get('open_id', 'microsoft_client_secret');
		$this->redirect_uri = $settings->get('open_id', 'microsoft_redirect_uri');

		//
		// Replace the {$domain_name} placeholder for user in redirect_uri
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

		// Get the field mapping for the Microsoft claim to the user table field in v_users
		$mapping = $settings->get('open_id', 'microsoft_username_mapping');

		// When errors are allowed and the field mapping is empty throw an error
		if (!$this->suppress_errors && empty($mapping)) throw new \InvalidArgumentException('microsoft_username_mapping must not be empty');

		// When errors are allowed and the mapping does not have an equals (=) sign throw an error
		if (!$this->suppress_errors && !str_contains($mapping, '=')) throw new \InvalidArgumentException('microsoft_username_mapping must be in the form of microsoft_oidc_field=user_column');

		// Map the Microsoft OIDC field to the user table field to validate the user exists
		[$microsoft_field, $table_field] = explode('=', $mapping, 2);

		// Trim the whitespace for field names and store in the object
		$this->microsoft_field = trim($microsoft_field);
		$this->table_field = trim($table_field);

		// Test that both fields for lookup are not empty
		if (!$this->suppress_errors && empty($this->microsoft_field)) throw new \InvalidArgumentException('Microsoft OpenID Connect field must not be empty in microsoft_username_mapping default settings');
		if (!$this->suppress_errors && empty($this->table_field)) throw new \InvalidArgumentException('Users table field must not be empty in microsoft_username_mapping default settings');

		// Test the 'table_field' column exists in the v_users table
		if (!$this->suppress_errors && !empty($this->table_field) && !$settings->database()->column_exists(database::TABLE_PREFIX . 'users', $this->table_field)) throw new \InvalidArgumentException("Users table field $this->table_field does not exist in the users table");

		// Get the microsoft_metadata_domain
		$domain = $settings->get('open_id', 'microsoft_metadata_domain');

		// When errors are allowed and domain is empty throw an error
		if (empty($domain) && !$this->suppress_errors) throw new \InvalidArgumentException('microsoft_metadata_domain must not be empty');

		// We must use a secure protocol to connect
		if (str_starts_with($domain, 'http://')) $domain = substr($domain, 7);		//remove http
		if (!str_starts_with($domain, 'https://')) $domain = 'https://' . $domain;	//add https

		// Get the microsoft_metadata_path
		// e.g. /common/v2.0/.well-known/openid-configuration
		$path = $settings->get('open_id', 'microsoft_metadata_path');

		// When errors are allowed and path is empty throw an error
		if (empty($path) && !$this->suppress_errors) throw new \InvalidArgumentException('microsoft_metadata_path must not be empty');

		// Ensure path starts with a slash (/)
		if (!str_starts_with($path, '/')) $path = '/' . $path;

		// Form completed discovery URI
		$this->discovery_url = $domain . $path;

		// Set the scope
		$this->scope = $scope;
	}

	/**
	 * Authenticate the user against Microsoft Entra ID.
	 *
	 * @return array Returns an array with user details or an empty array when authentication failed
	 * @throws \Random\RandomException
	 * @global database $database
	 */
	public function authenticate(): array {

		//
		// Initialize the result as an array with failed authentication
		//
		$result = [];
		$result["authorized"] = false;

		$this->load_discovery();
		if (!isset($_GET['code'])) {
			//detect redirection loop
			if (!empty($_SESSION['open_id_authorize'])) {
				$_SESSION['open_id_authorize'] = false;
				//redirect loop detected
				die('unable to redirect');
			}

			//
			// Set the state and code_verifier
			//
			$_SESSION['open_id_state'] = bin2hex(random_bytes(5));
			$_SESSION['open_id_code_verifier'] = bin2hex(random_bytes(50));
			$_SESSION['open_id_authorize'] = true;

			//
			// Send the authentication request to the authorization server
			//
			$authorize_url = $this->get_authorization_url();

			//
			// Not logged in to Microsoft yet
			//
			header('Location: ' . $authorize_url);
			exit();
		} else {

			//
			// Validate the state parameter (CSRF protection)
			//
			if (empty($_GET['state']) || ($_SESSION['open_id_state'] ?? null) !== $_GET['state']) {
				die('Authorization server returned an invalid state parameter');
			}

			//
			// The authorization server can respond with an error
			//
			if (isset($_GET['error'])) {
				die('Authorization server returned an error: ' . htmlspecialchars($_GET['error']));
			}

			//
			// Get the code
			//
			$code = $_REQUEST['code'];

			//
			// Send the code to Microsoft to get back the token array
			//
			$token = $this->exchange_code_for_token($code);

			//
			// Validate the access_token
			//
			if (isset($token['access_token'])) {

				//
				// Set the tokens
				//
				$access_token = $token['access_token'];
				$id_token = $token['id_token'] ?? '';

				//
				// Build the claim set. Prefer the id_token claims (which reliably
				// contain preferred_username/email for work, school and personal
				// accounts), then merge anything extra from the userinfo endpoint.
				//
				$claims = $this->decode_id_token($id_token);
				$user_info = $this->get_user_info($access_token);
				if (is_array($user_info)) {
					$claims = array_merge($user_info, $claims);
				}

				//
				// Make sure the claim we map on is present
				//
				if (!empty($claims[$this->microsoft_field])) {
					global $database;
					$sql  = 'select user_uuid, username, u.domain_uuid, d.domain_name';
					$sql .= ' from v_users u';
					$sql .=	' left outer join v_domains d on d.domain_uuid = u.domain_uuid';
					$sql .=	" where $this->table_field = :$this->table_field";
					$sql .= " and user_enabled = 'true'";
					$sql .=	' limit 1';

					//
					// Use the claim from Microsoft to find the user in the v_users table
					//
					$parameters = [];
					$parameters[$this->table_field] = $claims[$this->microsoft_field];

					//
					// Get the user array from the local database
					//
					$user = $database->select($sql, $parameters, 'row');
					if (empty($user)) {
						//
						// The user was not found or rejected. Authentication failed.
						//
						return $result;
					}
				} else {
					//
					// Microsoft did not return the mapped claim or the user cancelled
					//
					return $result;
				}

				//
				// Save necessary tokens so we can logout
				//
				$_SESSION['open_id_access_token'] = $access_token;
				$_SESSION['open_id_session_token'] = $id_token;
				$_SESSION['open_id_end_session'] = $this->end_session_endpoint;

				//
				// Set up the response from the plugin to the caller
				//
				$result["plugin"] = self::class;
				$result["domain_uuid"] = $user['domain_uuid'];
				$result["domain_name"] = $user['domain_name'];
				$result["username"] = $user['username'];
				$result["user_uuid"] = $user['user_uuid'];

				$result["user_email"] = $claims['email'] ?? $claims['preferred_username'] ?? $claims[$this->microsoft_field];
				$result["authorized"] = true;

				//
				// Remove the failed login message
				//
				$_SESSION['authorized'] = true;

				//
				// Return the filled array
				//
				return $result;
			}
		}

		return $result;
	}

	/**
	 * Loads Microsoft's OIDC discovery document and sets the endpoints.
	 */
	protected function load_discovery() {
		$ch = curl_init($this->discovery_url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$discovery_json = curl_exec($ch);
		curl_close($ch);
		$discovery = json_decode($discovery_json, true);
		if ($discovery) {
			$this->auth_endpoint = $discovery['authorization_endpoint'] ?? null;
			$this->token_endpoint = $discovery['token_endpoint'] ?? null;
			$this->userinfo_endpoint = $discovery['userinfo_endpoint'] ?? null;
			$this->end_session_endpoint = $discovery['end_session_endpoint'] ?? null;
		}
	}

	/**
	 * Generates the authorization URL to which users should be redirected.
	 *
	 * @return string The Microsoft authorization URL.
	 */
	public function get_authorization_url(): string {
		// Generate a state value for CSRF protection.
		$this->state = $_SESSION['open_id_state'];

		$params = [
			'client_id' => $this->client_id,
			'redirect_uri' => $this->redirect_uri,
			'response_type' => 'code',
			'response_mode' => 'query',
			'scope' => $this->scope,
			'state' => $_SESSION['open_id_state'],
			// Let the user pick which Microsoft account to sign in with
			'prompt' => 'select_account',
		];

		return $this->auth_endpoint . '?' . http_build_query($params);
	}

	/**
	 * Exchanges the authorization code for tokens.
	 *
	 * @param string $code The authorization code received from Microsoft.
	 * @return array|null An associative array containing tokens or null on failure.
	 */
	public function exchange_code_for_token(string $code): ?array {
		$params = [
			'code' => $code,
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
			'redirect_uri' => $this->redirect_uri,
			'grant_type' => 'authorization_code',
			'scope' => $this->scope,
		];

		$ch = curl_init($this->token_endpoint);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$response = curl_exec($ch);
		curl_close($ch);
		$tokenData = json_decode($response, true);

		return $tokenData;
	}

	/**
	 * Retrieves user information using the access token (Microsoft Graph OIDC userinfo).
	 *
	 * @param string $access_token The access token.
	 * @return array|null An associative array of user info, or null on failure.
	 */
	public function get_user_info(string $access_token): ?array {
		if (empty($this->userinfo_endpoint)) {
			return null;
		}
		$ch = curl_init($this->userinfo_endpoint);
		curl_setopt($ch, CURLOPT_HTTPHEADER, [
			"Authorization: Bearer " . $access_token
		]);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$response = curl_exec($ch);
		curl_close($ch);
		return json_decode($response, true);
	}

	/**
	 * Decode the payload of a JWT id_token without verifying the signature.
	 * The id_token comes directly from Microsoft over the back-channel TLS
	 * token request, so it is trusted for claim extraction here.
	 *
	 * @param string $id_token
	 * @return array Decoded claims, or empty array on failure.
	 */
	protected function decode_id_token(string $id_token): array {
		if (empty($id_token)) {
			return [];
		}
		$parts = explode('.', $id_token);
		if (count($parts) < 2) {
			return [];
		}
		$payload = strtr($parts[1], '-_', '+/');
		$padding = strlen($payload) % 4;
		if ($padding > 0) {
			$payload .= str_repeat('=', 4 - $padding);
		}
		$decoded = json_decode(base64_decode($payload), true);
		return is_array($decoded) ? $decoded : [];
	}

	public static function get_banner_image(settings $settings): string {
		// Use a configured image if present, otherwise render a branded button
		$banner = $settings->get('open_id', 'microsoft_image', '');
		if (!empty($banner) && file_exists($banner)) {
			$file_handle = fopen($banner, 'rb');
			$data = base64_encode(fread($file_handle, filesize($banner)));
			fclose($file_handle);
			return "<img src='data:image/png;base64,$data' alt='Sign in with Microsoft'/>";
		}

		// Microsoft-branded fallback button with the four-square logo
		$logo = "<span style='display:inline-grid;grid-template-columns:9px 9px;grid-gap:2px;margin-right:10px;'>"
			. "<span style='width:9px;height:9px;background:#f25022;'></span>"
			. "<span style='width:9px;height:9px;background:#7fba00;'></span>"
			. "<span style='width:9px;height:9px;background:#00a4ef;'></span>"
			. "<span style='width:9px;height:9px;background:#ffb900;'></span>"
			. "</span>";

		return "<div"
				. " style='display:inline-flex;align-items:center;"
				. " border:1px solid #8c8c8c;"
				. " border-radius:4px;"
				. " padding:8px 16px;"
				. " background-color:#fff;"
				. " color:#5e5e5e;"
				. " font-family:\"Segoe UI\",Arial,sans-serif;"
				. " font-size:15px;"
				. " text-decoration:none;"
				. " cursor:pointer;'>"
				. $logo
				. "Sign in with Microsoft"
				. "</div>"
		;
	}

	public static function get_banner_css_class(settings $settings): string {
		return $settings->get('open_id', 'open_id_css_class', 'banner_css_class');
	}

	public static function pre_session_destroy_logout_event(string $logout_destination) {

	}

	public static function post_session_destroy_logout_event(string $logout_destination) {

	}
}

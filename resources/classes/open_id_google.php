<?php

class open_id_google implements open_id_authenticator {

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
	 * When true, the global default settings are set to use a globally unique username
	 * @var bool
	 */
	protected $unique_username;

	/**
	 * When true, no errors will be thrown. When false, errors can be thrown to help with debugging
	 * @var bool
	 */
	protected $suppress_errors;

	/**
	 * Field name that contains the OpenID Connect field
	 * @var string
	 */
	protected $google_field;

	/**
	 * Field name that contains the users table field
	 * @var string
	 */
	protected $table_field;

	/**
	 * Set up the Google URL parameters and object variables
	 *
	 * @param string $client_id     Your Google Client ID.
	 * @param string $client_secret Your Google Client Secret.
	 * @param string $redirect_uri  The redirect URI registered with Google.
	 * @param string $scope         Space-separated scopes (default: "openid email profile").
	 */
	public function __construct($scope = "openid email profile") {
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

		// Set up the console.cloud.google.com settings
		$this->client_id = $settings->get('open_id', 'google_client_id');
		$this->client_secret = $settings->get('open_id', 'google_client_secret');
		$this->redirect_uri = $settings->get('open_id', 'google_redirect_uri');

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

		// Get the field mapping for the google email address to the user email address or username field in v_users table
		$mapping = $settings->get('open_id', 'google_username_mapping');

		// When errors are allowed and the field mapping is empty throw an error
		if (!$this->suppress_errors && empty($mapping)) throw new \InvalidArgumentException('google_map_fields must not be empty');

		// When errors are allowed and the mapping does not have an equals (=) sign throw an error
		if (!$this->suppress_errors && !str_contains($mapping, '=')) throw new \InvalidArgumentException('google_username_mapping must be in the form of google_oidc_field=user_column');

		// Map the Google OpenID Connect (OIDC) field to the user table field to validate the user exists
		[$google_field, $table_field] = explode('=', $mapping, 2);

		// Trim the whitespace for field names and store in the object
		$this->google_field = trim($google_field);
		$this->table_field = trim($table_field);

		// Test that both fields for lookup are not empty
		if (!$this->suppress_errors && empty($this->google_field)) throw new \InvalidArgumentException('Google OpenID Connect field must not be emtpy in google_oidc_field default settings');
		if (!$this->suppress_errors && empty($this->table_field)) throw new \InvalidArgumentException('Users table field must not be emtpy in google_oidc_field default settings');

		// Test the 'table_field' column exists in the v_users table
		if (!$this->suppress_errors && !empty($this->table_field) && !$settings->database()->column_exists(database::TABLE_PREFIX . 'users', $this->table_field)) throw new \InvalidArgumentException("Users table field $this->table_field does not exist in the users table");

		// Get the google_metadata_domain
		$domain = $settings->get('open_id', 'google_metadata_domain');

		// When errors are allowed and domain is empty throw an error
		if (empty($domain) && !$this->suppress_errors) throw new \InvalidArgumentException('google_metadata_domain must not be empty');

		// We must use a secure protocol to connect
		if (str_starts_with($domain, 'http://')) $domain = substr($domain, 7);		//remove http
		if (!str_starts_with($domain, 'https://')) $domain = 'https://' . $domain;	//add https

		// Get the google_metadata_path
		$path = $settings->get('open_id', 'google_metadata_path');

		// When errors are allowed and path is empty throw an error
		if (empty($path) && !$this->suppress_errors) throw new \InvalidArgumentException('google_metadata_path must not be empty');

		// Ensure path starts with a slash (/)
		if (!str_starts_with($path, '/')) $path = '/' . $path;

		// Form completed URI
		$this->discovery_url = $domain . $path;

		// Set the scope
		$this->scope = $scope;
	}

	/**
	 * When successful, the array with the authorized key set to true with user details. When the function fails to authenticate a user a boolean false is returned
	 * @global database $database
	 * @return array Returns an array with user details or an empty array when authentication failed
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
			if (!empty($_SESSION['open_id_authorize']) && $_SESSION['open_id_authorize']) {
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
			// Not logged in to goolge yet
			//
			header('Location: ' . $authorize_url);
			exit();
		} else {

			//
			// Get the code
			//
			$code = $_REQUEST['code'];

			//
			// Send the code to Google to get back the token array
			//
			$token = $this->exchange_code_for_token($code);

			//
			// Validate the access_token
			//
			if (isset($token['access_token'])) {

				//
				// Set the access tokens
				//
				$access_token = $token['access_token'];
				$id_token = $token['id_token'];

				//
				// Get user info
				//
				$user_info = $this->get_user_info($access_token);
				if (isset($user_info['email'])) {
					global $database;
					$sql  = 'select user_uuid, username, u.domain_uuid, d.domain_name';
					$sql .= ' from v_users u';
					$sql .=	' left outer join v_domains d on d.domain_uuid = u.domain_uuid';
					$sql .=	" where $this->table_field = :$this->table_field";
					$sql .= " and user_enabled = 'true'";
					$sql .=	' limit 1';

					//
					// Use the field from google to find user in the v_users table
					//
					$parameters = [];
					$parameters[$this->table_field] = $user_info[$this->google_field];

					//
					// Get the user array from the local database
					//
					$user = $database->select($sql, $parameters, 'row');
					if (empty($user)) {
						//
						// The user was not found so authentication failed so return empty result
						//
						return $result;
					}
				} else {
					//
					// Google did not authenticate the access token or user cancelled so return empty result
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

				$result["user_email"] = $user_info['email'];
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
	 * Loads Google's OIDC discovery document and sets the endpoints.
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
			$this->end_session_endpoint = $discovery['revocation_endpoint'] ?? null;
		}
	}

	/**
	 * Generates the authorization URL to which users should be redirected.
	 *
	 * @return string The Google authorization URL.
	 */
	public function get_authorization_url() {
		// Generate a state value for CSRF protection.
		$this->state = $_SESSION['open_id_state'];

		$params = [
			'client_id' => $this->client_id,
			'redirect_uri' => $this->redirect_uri,
			'response_type' => 'code',
			'scope' => $this->scope,
			'state' => $_SESSION['open_id_state'],
			'prompt' => 'consent',
			'access_type' => 'offline'
		];

		return $this->auth_endpoint . '?' . http_build_query($params);
	}

	/**
	 * Exchanges the authorization code for tokens.
	 *
	 * @param string $code The authorization code received from Google.
	 * @return array|null An associative array containing tokens or null on failure.
	 */
	public function exchange_code_for_token($code) {
		$params = [
			'code' => $code,
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
			'redirect_uri' => $this->redirect_uri,
			'grant_type' => 'authorization_code'
		];

		$ch = curl_init($this->token_endpoint);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$response = curl_exec($ch);
		curl_close($ch);
		$tokenData = json_decode($response, true);

		// You might want to add error checking here.
		return $tokenData;
	}

	/**
	 * Retrieves user information using the access token.
	 *
	 * @param string $access_token The access token.
	 * @return array|null An associative array of user info, or null on failure.
	 */
	public function get_user_info($access_token) {
		$ch = curl_init($this->userinfo_endpoint);
		curl_setopt($ch, CURLOPT_HTTPHEADER, [
			"Authorization: Bearer " . $access_token
		]);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$response = curl_exec($ch);
		curl_close($ch);
		return json_decode($response, true);
	}

	public static function get_banner_image(): string {
		global $settings;
		$google_banner = $settings->get('open_id', 'google_image', '');
		$text = new text();
		$text_array = $text->get();
		$alt = $text_array['alt-banner'] ?? 'Sign-in Using Google';
		if (file_exists($google_banner)) {
			$file_handle = fopen($google_banner, 'rb');
			$data = base64_encode(fread($file_handle, 2182));
			fclose($file_handle);
			return "<img src='data:image/png;base64,$data' alt='$alt'/>";
		}
		return $alt;
	}
}

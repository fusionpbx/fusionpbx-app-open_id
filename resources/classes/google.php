<?php

class google implements openid {

	protected $client_id;
	protected $client_secret;
	protected $redirect_uri;
	protected $scope;
	protected $state;
	protected $discovery_url = "https://accounts.google.com/.well-known/openid-configuration";
	protected $auth_endpoint;
	protected $token_endpoint;
	protected $userinfo_endpoint;
	protected $end_session_endpoint;

	/**
	 * Constructor.
	 *
	 * @param string $client_id     Your Google Client ID.
	 * @param string $client_secret Your Google Client Secret.
	 * @param string $redirect_uri  The redirect URI registered with Google.
	 * @param string $scope         Space-separated scopes (default: "openid email profile").
	 */
	public function __construct($scope = "openid email profile") {
		global $settings;
		$this->client_id = $settings->get('openid', 'openid_client_id');
		$this->client_secret = $settings->get('openid', 'openid_client_secret');
		$this->redirect_uri = $settings->get('openid', 'openid_redirect_uri');
		$this->scope = $scope;
	}

	/**
	 * When successful, the array with the authorized key set to true with user details. When the function fails to authenticate a user a boolean false is returned
	 * @global database $database
	 * @return bool|array Returns an array with user details or false when failed authentication
	 */
	public function authenticate() {

		//
		// Initialize the result as an array with failed authentication
		//
		$result = [];
		$result["authorized"] = false;

		$this->load_discovery();
		if (!isset($_GET['code'])) {
			//detect redirection loop
			if (!empty($_SESSION['openid_authorize']) && $_SESSION['openid_authorize']) {
				$_SESSION['openid_authorize'] = false;
				//redirect loop detected
				die('unable to redirect');
			}

			//
			// Set the state and code_verifier
			//
			$_SESSION['openid_state'] = bin2hex(random_bytes(5));
			$_SESSION['openid_code_verifier'] = bin2hex(random_bytes(50));
			$_SESSION['openid_authorize'] = true;

			//
			// Send the authentication request to the authorization server
			//
			$authorize_url = $this->get_authorization_url();

			//
			// Not logged in yet
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
					$sql = "select user_uuid, username, u.domain_uuid, d.domain_name from v_users u "
							. "left outer join v_domains d on d.domain_uuid = u.domain_uuid "
							. "where user_email = :user_email and user_enabled = 'true' "
							. "limit 1 ";
					$parameters = [];

					//
					// Username is the email address of user
					//
					$parameters['user_email'] = $user_info['email'];

					//
					// Get the user array from the local database
					//
					$user = $database->select($sql, $parameters, 'row');
					if (empty($user)) {
						//
						// The user email was not found so authentication failed
						//
						return false;
					}
				} else {
					//
					// Google did not authenticate the access token or user cancelled
					//
					return false;
				}

				//
				// Save necessary tokens so we can logout
				//
				$_SESSION['openid_access_token'] = $access_token;
				$_SESSION['openid_session_token'] = $id_token;
				$_SESSION['openid_end_session'] = $this->end_session_endpoint;

				//
				// Set up the response from the plugin to the caller
				//
				$result["plugin"] = "google";
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
				// Return the array
				//
				return $result;
			}
		}

		return false;
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
		$this->state = $_SESSION['openid_state'];

		$params = [
			'client_id' => $this->client_id,
			'redirect_uri' => $this->redirect_uri,
			'response_type' => 'code',
			'scope' => $this->scope,
			'state' => $_SESSION['openid_state'],
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
		if (file_exists($google_banner)) {
			$file_handle = fopen($google_banner, 'rb');
			$data = base64_encode(fread($file_handle, 2182));
			fclose($file_handle);
			return $data;
		}
		return '';
	}

	public static function get_banner_url(): string {
		return '/app/openid/openid.php?action=openid_google';
	}

	public static function get_banner_alt(): string {
		return 'Sign-in With Google';
	}
}

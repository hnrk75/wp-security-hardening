<?php
/**
 * Plugin Name: Security Hardening
 * Plugin URI:  https://github.com/hnrk75/wp-security-hardening
 *
 * Description: Basic security hardening: enforces disabled registration, disables XML-RPC and application passwords, requires two-factor authentication when the Two Factor plugin is active, throttles failed logins per IP and account, hides usernames and the WordPress version, sends security headers and emails the admin when a user is created or becomes administrator/editor.
 *
 * Version:     1.3.2
 * Author:      Henrik Pettersson <henrik.pettersson@knowit.se>
 * License:     MIT License
 *
 * @package Security_Hardening
 */

/**
 * Registration is always disabled and new users never get more than the subscriber role,
 * regardless of what is stored in the database.
 */
add_filter( 'pre_option_users_can_register', '__return_zero' );
add_filter(
	'pre_option_default_role',
	function () {
		return 'subscriber';
	}
);

/**
 * Disable XML-RPC completely (brute force via system.multicall, pingbacks).
 */
add_filter( 'xmlrpc_enabled', '__return_false' );
add_filter( 'xmlrpc_methods', '__return_empty_array' );
add_filter(
	'wp_headers',
	function ( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}
);

/**
 * Application passwords bypass the regular login and are not used.
 */
add_filter( 'wp_is_application_passwords_available', '__return_false' );

/**
 * When the Two Factor plugin is active, users without two-factor authentication
 * are sent to their profile until they have set it up.
 */
add_action(
	'admin_init',
	function () {
		if ( ! class_exists( 'Two_Factor_Core' ) || wp_doing_ajax() || 'profile.php' === $GLOBALS['pagenow'] ) {
			return;
		}

		if ( Two_Factor_Core::is_user_using_two_factor( get_current_user_id() ) ) {
			return;
		}

		wp_safe_redirect( admin_url( 'profile.php#two-factor-options' ) );
		exit;
	}
);

add_action(
	'admin_notices',
	function () {
		if ( ! class_exists( 'Two_Factor_Core' ) || 'profile.php' !== $GLOBALS['pagenow'] || Two_Factor_Core::is_user_using_two_factor( get_current_user_id() ) ) {
			return;
		}

		wp_admin_notice(
			'<strong>Tvåstegsverifiering krävs.</strong> Välj en metod under tvåstegsverifiering längre ner på sidan och spara innan du kan använda adminpanelen.',
			array( 'type' => 'warning' )
		);
	}
);

/**
 * Prevent logged-out visitors from enumerating usernames.
 */
add_filter(
	'rest_endpoints',
	function ( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		foreach ( array_keys( $endpoints ) as $route ) {
			if ( str_starts_with( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}
);

add_action(
	'template_redirect',
	function () {
		if ( is_user_logged_in() ) {
			return;
		}

		if ( is_author() || isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only checks whether the parameter exists.
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	},
	1
);

add_filter(
	'wp_sitemaps_add_provider',
	function ( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	},
	10,
	2
);

add_filter(
	'oembed_response_data',
	function ( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}
);

/**
 * Same error message whether the username does not exist or the password is wrong.
 */
add_filter(
	'authenticate',
	function ( $user ) {
		if ( is_wp_error( $user ) && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'invalid_email', 'incorrect_password' ) ) ) {
			return new WP_Error( 'invalid_credentials', '<strong>Fel:</strong> Felaktigt användarnamn eller lösenord.' );
		}

		return $user;
	},
	99
);

/**
 * Login throttling: after 5 failed logins for the same account from the same IP within
 * 15 minutes, that combination is locked out for 15 minutes.
 *
 * Counting per IP and account works on any host: REMOTE_ADDR cannot be spoofed, and if
 * the host has a proxy in front (so all visitors share its IP), only the attacked
 * account is locked, not every user.
 */
const SECURITY_HARDENING_MAX_ATTEMPTS = 5;
const SECURITY_HARDENING_LOCKOUT      = 15 * MINUTE_IN_SECONDS;

/**
 * Transient key for the current visitor's IP and the given login, or an empty string
 * when either is unknown. Username and email of the same user give the same key.
 *
 * @param string $username Username or email entered in the login form.
 * @return string
 */
function security_hardening_login_key( $username ) {
	$ip       = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	$username = strtolower( trim( (string) $username ) );

	if ( ! $ip || ! $username ) {
		return '';
	}

	$user    = get_user_by( is_email( $username ) ? 'email' : 'login', $username );
	$account = $user ? 'user:' . $user->ID : 'name:' . $username;

	return 'security_hardening_login_' . md5( $ip . '|' . $account );
}

/**
 * Runs after core has checked the credentials (priority 20), so a locked-out login
 * is rejected even when the password is correct.
 */
add_filter(
	'authenticate',
	function ( $user, $username ) {
		$key  = security_hardening_login_key( $username );
		$data = $key ? get_transient( $key ) : false;

		if ( empty( $data['locked_until'] ) || $data['locked_until'] <= time() ) {
			return $user;
		}

		$minutes = (int) ceil( ( $data['locked_until'] - time() ) / MINUTE_IN_SECONDS );

		return new WP_Error(
			'too_many_attempts',
			sprintf( '<strong>Fel:</strong> För många misslyckade inloggningar. Försök igen om %d %s.', $minutes, 1 === $minutes ? 'minut' : 'minuter' )
		);
	},
	30,
	2
);

add_action(
	'wp_login_failed',
	function ( $username ) {
		$key = security_hardening_login_key( $username );

		if ( ! $key ) {
			return;
		}

		$data = get_transient( $key );
		$data = is_array( $data ) ? $data : array( 'count' => 0 );

		// Attempts during a lockout do not extend it.
		if ( ! empty( $data['locked_until'] ) && $data['locked_until'] > time() ) {
			return;
		}

		++$data['count'];

		if ( $data['count'] >= SECURITY_HARDENING_MAX_ATTEMPTS ) {
			$data = array(
				'count'        => 0,
				'locked_until' => time() + SECURITY_HARDENING_LOCKOUT,
			);
		}

		set_transient( $key, $data, SECURITY_HARDENING_LOCKOUT );
	}
);

add_action(
	'wp_login',
	function ( $user_login ) {
		$key = security_hardening_login_key( $user_login );

		if ( $key ) {
			delete_transient( $key );
		}
	}
);

/**
 * The lost password form shows the same confirmation whether the account exists or not.
 */
add_action(
	'lostpassword_post',
	function ( $errors, $user_data ) {
		if ( $user_data || 'wp-login.php' !== $GLOBALS['pagenow'] || 'empty_username' === $errors->get_error_code() ) {
			return;
		}

		wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', wp_login_url() ) );
		exit;
	},
	10,
	2
);

/**
 * Do not expose the WordPress version.
 */
remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );

/**
 * Security headers.
 */
add_action(
	'send_headers',
	function () {
		header_remove( 'X-Powered-By' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );

		if ( 'production' === wp_get_environment_type() && is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}
	}
);

/**
 * Email the admin when a user is created or gets a role with editing capabilities.
 *
 * @param string $subject Email subject.
 * @param int    $user_id User ID.
 */
function security_hardening_notify( $subject, $user_id ) {
	$user = get_userdata( $user_id );

	if ( ! $user ) {
		return;
	}

	$actor = wp_get_current_user()->user_login;
	$ip    = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

	$message = implode(
		"\n",
		array(
			'Användare: ' . $user->user_login . ' (ID ' . $user->ID . ')',
			'E-post: ' . $user->user_email,
			'Roller: ' . implode( ', ', $user->roles ),
			'Utförd av: ' . ( $actor ? $actor : 'okänd/utloggad' ),
			'IP: ' . ( $ip ? $ip : 'okänd' ),
			'Webbplats: ' . home_url(),
		)
	);

	wp_mail( get_option( 'admin_email' ), '[' . wp_parse_url( home_url(), PHP_URL_HOST ) . '] ' . $subject, $message );
}

add_action(
	'user_register',
	function ( $user_id ) {
		security_hardening_notify( 'Ny användare skapad', $user_id );
	}
);

/**
 * New users are already covered by user_register, so only role changes on existing users are reported here.
 */
add_action(
	'set_user_role',
	function ( $user_id, $role, $old_roles ) {
		if ( $old_roles && in_array( $role, array( 'administrator', 'editor' ), true ) && ! in_array( $role, $old_roles, true ) ) {
			security_hardening_notify( 'Användare fick rollen ' . $role, $user_id );
		}
	},
	10,
	3
);

/**
 * Plugins that grant extra roles use add_role(), which does not trigger set_user_role.
 */
add_action(
	'add_user_role',
	function ( $user_id, $role ) {
		if ( in_array( $role, array( 'administrator', 'editor' ), true ) ) {
			security_hardening_notify( 'Användare fick rollen ' . $role, $user_id );
		}
	},
	10,
	2
);

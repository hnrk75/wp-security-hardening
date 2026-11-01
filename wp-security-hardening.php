<?php
/**
 * Plugin Name: Security Hardening
 * Plugin URI:  https://github.com/hnrk75/wp-security-hardening
 *
 * Description: Basic security hardening: enforces disabled registration, disables XML-RPC and application passwords, requires two-factor authentication when the Two Factor plugin is active, throttles failed logins per IP and account and against password spraying, hides usernames and the WordPress version, sends security headers and emails the admin when a user is created or gains privileged capabilities.
 *
 * Version:     1.4.0
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
 * Login throttling per IP and account, so a shared proxy IP never locks out every user.
 */
const SECURITY_HARDENING_MAX_ATTEMPTS = 5;
const SECURITY_HARDENING_LOCKOUT      = 15 * MINUTE_IN_SECONDS;

/**
 * Transient key for IP + account. Username and email of a user give the same key.
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
 * Password spraying: after failures against this many accounts, an IP may not try new
 * accounts. Known accounts keep working, so users behind a shared proxy IP are not locked out.
 */
const SECURITY_HARDENING_MAX_ACCOUNTS_PER_IP = 10;
const SECURITY_HARDENING_KNOWN_ACCOUNTS_TTL  = 30 * DAY_IN_SECONDS;

/**
 * Transient key for the current IP.
 *
 * @return string
 */
function security_hardening_ip_key() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

	return $ip ? 'security_hardening_ip_' . md5( $ip ) : '';
}

/**
 * Remaining lockout in seconds, or 0.
 *
 * @param string $key Transient key.
 * @return int
 */
function security_hardening_locked_for( $key ) {
	$data = $key ? get_transient( $key ) : false;

	return ( is_array( $data ) && ! empty( $data['locked_until'] ) ) ? max( 0, $data['locked_until'] - time() ) : 0;
}

/**
 * Transient key for accounts that have logged in from the current IP.
 *
 * @return string
 */
function security_hardening_known_key() {
	$ip_key = security_hardening_ip_key();

	return $ip_key ? str_replace( '_ip_', '_known_', $ip_key ) : '';
}

/**
 * Known: tried during the lockout window, or logged in from this IP within 30 days.
 *
 * @param string $account_key Key from security_hardening_login_key().
 * @return bool
 */
function security_hardening_is_known_account( $account_key ) {
	if ( ! $account_key ) {
		return false;
	}

	if ( false !== get_transient( $account_key ) ) {
		return true;
	}

	$known = get_transient( security_hardening_known_key() );

	return is_array( $known ) && isset( $known[ $account_key ] );
}

// After core's credential check (priority 20), so a correct password is rejected too.
add_filter(
	'authenticate',
	function ( $user, $username ) {
		$account_key = security_hardening_login_key( $username );
		$seconds     = security_hardening_locked_for( $account_key );

		if ( ! security_hardening_is_known_account( $account_key ) ) {
			$seconds = max( $seconds, security_hardening_locked_for( security_hardening_ip_key() ) );
		}

		if ( ! $seconds ) {
			return $user;
		}

		$minutes = (int) ceil( $seconds / MINUTE_IN_SECONDS );

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

		// --- Per IP and account ---
		$data = get_transient( $key );
		$data = is_array( $data ) ? $data : array( 'count' => 0 );

		// Attempts during a lockout do not extend it.
		if ( empty( $data['locked_until'] ) || $data['locked_until'] <= time() ) {
			++$data['count'];

			if ( $data['count'] >= SECURITY_HARDENING_MAX_ATTEMPTS ) {
				$data = array(
					'count'        => 0,
					'locked_until' => time() + SECURITY_HARDENING_LOCKOUT,
				);
			}

			set_transient( $key, $data, SECURITY_HARDENING_LOCKOUT );
		}

		// --- Per IP: distinct accounts ---
		$max_accounts = (int) apply_filters( 'security_hardening_max_accounts_per_ip', SECURITY_HARDENING_MAX_ACCOUNTS_PER_IP );
		$ip_key       = security_hardening_ip_key();

		if ( $max_accounts < 1 || ! $ip_key || security_hardening_locked_for( $ip_key ) ) {
			return;
		}

		$ip_data = get_transient( $ip_key );
		$ip_data = is_array( $ip_data ) ? $ip_data : array( 'accounts' => array() );

		$ip_data['accounts'][ $key ] = true;

		if ( count( $ip_data['accounts'] ) >= $max_accounts ) {
			$ip_data = array(
				'accounts'     => array(),
				'locked_until' => time() + SECURITY_HARDENING_LOCKOUT,
			);
		}

		set_transient( $ip_key, $ip_data, SECURITY_HARDENING_LOCKOUT );
	}
);

add_action(
	'wp_login',
	function ( $user_login ) {
		$key = security_hardening_login_key( $user_login );

		if ( ! $key ) {
			return;
		}

		delete_transient( $key );

		$known_key = security_hardening_known_key();
		$known     = get_transient( $known_key );
		$known     = is_array( $known ) ? $known : array();

		unset( $known[ $key ] );
		$known[ $key ] = time();

		$known = array_slice( $known, -500, null, true );

		set_transient( $known_key, $known, SECURITY_HARDENING_KNOWN_ACCOUNTS_TTL );
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
 * Security headers, also on the login page and in wp-admin.
 */
function security_hardening_send_headers() {
	if ( headers_sent() ) {
		return;
	}

	header_remove( 'X-Powered-By' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );

	if ( 'production' === wp_get_environment_type() && is_ssl() ) {
		header( 'Strict-Transport-Security: max-age=31536000' );
	}
}
add_action( 'send_headers', 'security_hardening_send_headers' );
add_action( 'login_init', 'security_hardening_send_headers' );
add_action( 'admin_init', 'security_hardening_send_headers' );

/**
 * WordPress defaults the display name to the login name, which is shown publicly.
 *
 * @param int $user_id User ID.
 */
function security_hardening_hide_login_in_display_name( $user_id ) {
	static $running = false;

	$user = get_userdata( $user_id );

	if ( $running || ! $user || strtolower( $user->display_name ) !== strtolower( $user->user_login ) ) {
		return;
	}

	$candidates = array(
		trim( $user->first_name . ' ' . $user->last_name ),
		$user->nickname,
		get_bloginfo( 'name' ),
	);

	foreach ( $candidates as $candidate ) {
		if ( '' !== $candidate && strtolower( $candidate ) !== strtolower( $user->user_login ) ) {
			$running = true;
			wp_update_user(
				array(
					'ID'           => $user_id,
					'display_name' => $candidate,
				)
			);
			$running = false;
			return;
		}
	}
}
add_action( 'user_register', 'security_hardening_hide_login_in_display_name', 20 );
add_action( 'profile_update', 'security_hardening_hide_login_in_display_name', 20 );

// Fix existing users once.
add_action(
	'admin_init',
	function () {
		if ( get_option( 'security_hardening_display_names_fixed' ) || ! current_user_can( 'edit_users' ) ) {
			return;
		}

		global $wpdb;

		// WP_User_Query cannot compare two columns.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$user_ids = $wpdb->get_col( "SELECT ID FROM {$wpdb->users} WHERE display_name = user_login" );

		foreach ( $user_ids as $user_id ) {
			security_hardening_hide_login_in_display_name( (int) $user_id );
		}

		update_option( 'security_hardening_display_names_fixed', time(), false );
	}
);

/**
 * Email the admin about a user change.
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
 * By capability, not role name, so custom roles count too.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function security_hardening_is_privileged( $user_id ) {
	$caps = (array) apply_filters(
		'security_hardening_privileged_caps',
		array( 'manage_options', 'edit_users', 'promote_users', 'create_users', 'install_plugins', 'edit_theme_options', 'edit_others_posts', 'unfiltered_html' )
	);

	// Fresh object: capabilities may have changed in this request.
	$user = new WP_User( $user_id );

	foreach ( $caps as $cap ) {
		if ( $user->has_cap( $cap ) ) {
			return true;
		}
	}

	return is_super_admin( $user_id );
}

// Roles and capabilities share one meta key, so this covers set_role(), add_role() and add_cap().
$security_hardening_was_privileged = array();

add_action(
	'update_user_meta',
	function ( $meta_id, $user_id, $meta_key ) use ( &$security_hardening_was_privileged ) {
		global $wpdb;

		if ( $wpdb->get_blog_prefix() . 'capabilities' === $meta_key ) {
			$security_hardening_was_privileged[ $user_id ] = security_hardening_is_privileged( $user_id );
		}
	},
	10,
	3
);

add_action(
	'updated_user_meta',
	function ( $meta_id, $user_id, $meta_key ) use ( &$security_hardening_was_privileged ) {
		global $wpdb;

		if ( $wpdb->get_blog_prefix() . 'capabilities' !== $meta_key || ! isset( $security_hardening_was_privileged[ $user_id ] ) ) {
			return;
		}

		$was = $security_hardening_was_privileged[ $user_id ];
		unset( $security_hardening_was_privileged[ $user_id ] );

		if ( ! $was && security_hardening_is_privileged( $user_id ) ) {
			security_hardening_notify( 'Användare fick utökade behörigheter', $user_id );
		}
	},
	10,
	3
);

add_action(
	'granted_super_admin',
	function ( $user_id ) {
		security_hardening_notify( 'Användare blev superadministratör', $user_id );
	}
);

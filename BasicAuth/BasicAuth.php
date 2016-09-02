<?php

class BasicAuthPlugin extends MantisPlugin {
    function register() {
        $this->name        = 'BasicAuth Plugin';
        $this->description = 'Looks for REMOTE_USER in SERVER environment and autologins user. The username can be modified using $g_sso_user_regex in config for handling Kerberos auth and stripping domain (e.g. /^(.*)@DOMAIN\.LOCAL$/i).';
        $this->version     = '0.03';
        $this->requires    = array( 'MantisCore' => '2.0.0' );
        $this->author      = 'David Schmidt';
        $this->contact     = 'david.schmidt -at- univie.ac.at';
        $this->url         = '';
    }

	/**
	 * Register event hooks for plugin.
	 */
	function hooks() {
		return array(
			'EVENT_CORE_READY' => 'autologin',
		);
	}

    function autologin() {
        if (auth_is_user_authenticated()  || (php_sapi_name() == "cli")) {
            return;
        }

        $t_login_method = config_get( 'login_method' );
        if ( $t_login_method != BASIC_AUTH ) {
            trigger_error( "Invalid login method. ($t_login_method)", ERROR );
        }

		$t_sso_regex = config_get( 'sso_user_regex' );
		if ( $t_sso_regex ) {
			preg_match($t_sso_regex, $_SERVER['REMOTE_USER'], $user_match);
			$t_username = $user_match[1];
		}
		else
		{
			$t_username = $_SERVER['REMOTE_USER'];
		}

		$t_user_id = user_get_id_by_name($t_username);
	
        if ( !$t_user_id ) {
            trigger_error( 'Invalid user. (' . $t_username . ')', ERROR );
        }

	$_SERVER['REMOTE_USER']	= $t_username;
	
        user_increment_login_count( $t_user_id );
        user_reset_failed_login_count_to_zero( $t_user_id );
        user_reset_lost_password_in_progress_count_to_zero( $t_user_id );
        auth_set_cookies($t_user_id, true);
        auth_set_tokens($t_user_id);
		
	$t_redirect_url = '';
	print_header_redirect( $t_redirect_url );
    }
}

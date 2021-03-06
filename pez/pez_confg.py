{
    "hooks" :
    [
        "rad_hook.py",
        "eap_gtc_hook.py",
        "eap_tls_hook.py",
        "eap_tls_data_hook.py",
        "eap_hook.py",
        "rad_stress_reporter.py",
        "eap_mschapv2_hook.py"
    ],
    "eap_fast":
    {
        "unauth_ciphers" :
        [
            "TLS_DH_anon_WITH_AES_128_CBC_SHA"
        ],
        "tunnel_pac_file_name" : "/tmp/+$$user+.pac",
        "auth_ciphers" :
        [
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_RC4_128_SHA"
        ],
        "use_tunnel_pac" : "$$use_tunnel_pac",
        "request_tunnel_pac" : "$$request_tunnel_pac",
        "authenticate_server" : "$$authenticate_server",
        "use_machine_pac" : "$$use_machine_pac",
        "request_authorization_pac" : "$$request_authorization_pac",
        "machine_pac_file_name" : ".\\run_env\\+$$user+.pac",
        "request_machine_pac" : "$$request_machine_pac",
        "tls_fragment_length" : 2048,
        "version" : 1,
        "configured_types" :
        [
            "$$EAP_FAST_configured_types"
        ],
        "use_authorization_pac" : "$$use_authorization_pac",
        "authorization_pac_file_name" : ".\\run_env\\authorization-+$$user+.pac"
    },
    "eap_md5" :
    {
        "password" : "$$psw"
    },
    "peap" :
    {
        "version" : "$$PEAP_V",
        "tls_fragment_length" : 2048,
        "configured_types" :
        [
            "$$PEAP_Type"
        ]
    },
    "applications" :
    {
        "configured" : "$$APP_TYPE"
    },
    "radius" :
    {
        "retries" : "$$retries",
        "dictionaries" :
        [
            "./dictionaries"
        ],
        "secret" : "$$secret",
        "host" : "$$host",
        "timeout" : "$$timeout",
        "attributes" :
        {
            "User-Password" :
            [
                "$$psw"
            ],
            "NAS-Port-Type" :
            [
               "Ethernet"
            ],
            "NAS-IP-Address" :
            [
                "$$NAS-IP"
            ],
            "User-Name" :
            [
                "$$user"
            ],
            "Session-Timeout" :
            [
                30
            ],
            "Calling-Station-Id": 
            [
                "01:23:45:67:<hind  ff:f1  ff:ff>"
            ],
            "Message-Authenticator" :
            [
                "xyz"
            ]            
   
        },
        "port" : "$$port"
    },
    "eap" :
    {
        "inner_identity" : "$$user",
        "configured_types" :
        [
            "$$eap_type"
        ],
        "identity" : "$$user"
    },
    "eap_tls" :
    {
        "reuse_session" : "$$eaptls_reuse_session",
        "user_key" : "$$eaptls_user_key_file",
        "user_cert" : "$$eaptls_user_cert_file",
        "tls_fragment_length" : 1002,
        "ca_cert" : "$$eaptls_ca_cert_file"
    },
    "logging" :
	{
		"hooks" :
		[
			"./log_hooks"
		],
		"onoff" : "off",
		"file" : "stdout",
		"level" : "Debug"
	},
    "stress" :
    {
        "repeat" : "$$repeat",
        "num_clients" : "$$clients",
        "num_tasks" : "$$tasks"
    },
    "leap" :
    {
        "username" : "$$user",
        "password" : "$$psw"
    },
    "eap_ms_chapv2" :
    {
        "new_password" : "$$psw", 
        "password" : "$$psw",
        "name" : "$$user"
    },
    "eap_gtc" :
    {
		"^CHALLENGE=Password:.*$" : "RESPONSE=+$$user+\\0+$$psw+",
        "^Password:.*$" : "$$psw"
    }

}
/*******************************************************************************
 * file:        pam_fortitokencloud.c
 * author:      James Botting <james@bottswanamedia.info>
 * description: PAM module to provide 2FA via FortiToken Cloud
*******************************************************************************/

#define FTC_PROMPT_MSG_PUSH "FortiToken OTP (Or Enter if Push Approved): "
#define FTC_PROMPT_MSG "FortiToken OTP: "

#define FTC_API_LOGIN_URL "https://ftc.fortinet.com:9696/api/v1/login"
#define FTC_API_AUTH_URL "https://ftc.fortinet.com:9696/api/v1/auth"
#define FTC_API_USER_URL "https://ftc.fortinet.com:9696/api/v1/user"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <curl/curl.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/*
 * Shamelessly stolen from CURL documentation
 * https://curl.se/libcurl/c/getinmemory.html
 */
struct MemoryStruct
{
	char *memory;
	size_t size;
};
 
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if( !ptr )
	{
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

/*
 * Exchange the client ID and secret for a Bearer token
 */
char* ftm_get_access_token(pam_handle_t *pamh, char *ftc_apptoken, char *ftc_appsecret)
{
	char* ftc_accesstoken;

	// Validate input
	if( ftc_apptoken == NULL || ftc_appsecret == NULL || strlen(ftc_apptoken) <= 0 || strlen(ftc_appsecret) <= 0 )
	{
		pam_syslog(pamh, LOG_ERR, "Invalid ftc_apptoken or ftc_appsecret supplied to ftm_get_access_token");
		return NULL;
	}

	// Setup CURL
	struct curl_slist* headers = NULL;
	struct MemoryStruct chunk;
	long http_code = 0;
	CURLcode res;
	CURL *curl;
	int i = 0;

	curl = curl_easy_init();
	if( curl )
	{
		// Create struct for response data
		chunk.memory = malloc(1);
		chunk.size = 0;

		// Create post data
		char postdata[512];
		if( (strlen(ftc_apptoken) + strlen(ftc_appsecret)) > 400 || sprintf(postdata, R"anydelim( {"client_id": "%s", "client_secret": "%s"} )anydelim", ftc_apptoken, ftc_appsecret) < 0 )
		{
			pam_syslog(pamh, LOG_ERR, "Unable to construct POST payload");
			return NULL;
		}

		// Configure Headers
		headers = curl_slist_append(headers, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt(curl, CURLOPT_URL, FTC_API_LOGIN_URL);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if( http_code >= 200 && http_code <= 299 && res == CURLE_OK )
		{
			// Find the start of the access token
			char *substr;
			substr = strstr(chunk.memory, "access_token");
			if( substr == NULL )
			{
				// Unable to find start of access_token in response data
				pam_syslog(pamh, LOG_ERR, "Unable to find access_token in response payload");
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(chunk.memory);
				return NULL;
			}

			// Find the length of the access_token
			int access_key_len = 0;
			char *startstring = substr + 16;
			for( i=0; i<strlen(startstring); i++ )
			{
				if( startstring[i] == '"' ) break;
				access_key_len++;
			}

			// Validate the length we have determined
			if( access_key_len <= 0 )
			{
				pam_syslog(pamh, LOG_ERR, "Unable to find access_token in response payload");
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(chunk.memory);
				return NULL;
			}

			if( access_key_len > 1024 )
			{
				pam_syslog(pamh, LOG_ERR, "Access key is > 1024 bytes, bailing");
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(chunk.memory);
				return NULL;
			}

			// Allocate memory for the new access token
			ftc_accesstoken = (char*)malloc(access_key_len + 1);
			if( ftc_accesstoken == NULL )
			{
				pam_syslog(pamh, LOG_ERR, "Unable to allocate %d bytes memory for access_token", access_key_len);
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(chunk.memory);
				return NULL;
			}

			// Copy substring into memory
			strncpy(ftc_accesstoken, startstring, access_key_len);
			ftc_accesstoken[access_key_len] = '\0';

			pam_syslog(pamh, LOG_DEBUG, "Token retrieved successfully %s", ftc_accesstoken);
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			free(chunk.memory);

			return ftc_accesstoken;
		}

		// A failure response here indicates that we have failed to aquire an access token
		// https://docs.fortinet.com/document/fortitoken-cloud/latest/rest-api/191897/post
		pam_syslog(pamh, LOG_ERR, "CURL Error; Response Code: %d, Error: %s", http_code, curl_easy_strerror(res));
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		free(chunk.memory);
		return NULL;
	}

	pam_syslog(pamh, LOG_ERR, "Failed to initialise CURL");
	return NULL;
}

/*
 * Create a user in the FMC Cloud Service, if they do not exist
 * If the user does not exist in the realm, they will be sent an invitation
 * Returns a PAM response code based on the server response
 */
int ftm_create_user(pam_handle_t *pamh, char *ftc_accesstoken, char *username)
{
	// Validate input
	if( username == NULL || ftc_accesstoken == NULL || strlen(username) <= 0 || strlen(ftc_accesstoken) <= 0 )
	{
		pam_syslog(pamh, LOG_ERR, "Invalid username or access key supplied to ftm_create_user");
		return PAM_AUTHINFO_UNAVAIL;
	}

	// Setup CURL
	struct curl_slist* headers = NULL;
	long http_code = 0;
	CURLcode res;
	CURL *curl;

	curl = curl_easy_init();
	if( curl )
	{
		// Create post data
		char postdata[512];
		if( (strlen(username) * 2) > 400 || sprintf(postdata, R"anydelim( {"username": "%s", "email": "%s"} )anydelim", username, username) < 0 )
		{
			pam_syslog(pamh, LOG_ERR, "Unable to construct POST payload");
			return PAM_AUTHINFO_UNAVAIL;
		}

		// Create auth header
		char access_header[512];
		if( strlen(ftc_accesstoken) > 480 || sprintf(access_header, "Authorization: Bearer %s", ftc_accesstoken) < 0 )
		{
			pam_syslog(pamh, LOG_ERR, "Unable to construct POST headers");
			return PAM_AUTHINFO_UNAVAIL;
		}

		// Configure Headers
		headers = curl_slist_append(headers, "Content-Type: application/json");
		headers = curl_slist_append(headers, access_header);

		// Set headers and request
		curl_easy_setopt(curl, CURLOPT_URL, FTC_API_USER_URL);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if( http_code >= 200 && http_code <= 299 && res == CURLE_OK )
		{
			// A 200 response indicates that we have created the user
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			return PAM_SUCCESS;
		}

		// A failure response here indicates that we have failed to create the user
		pam_syslog(pamh, LOG_ERR, "CURL Error; Response Code: %d, Error: %s", http_code, curl_easy_strerror(res));
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return PAM_AUTH_ERR;
	}

	pam_syslog(pamh, LOG_ERR, "Failed to initialise CURL");
	return PAM_AUTHINFO_UNAVAIL;
}

/*
 * Validate a user-entered code with the FTC Cloud Service.
 * Omit token to send the user a PUSH notification instead of validate a token
 * Returns a PAM response code based on the server response
 */
int ftm_validate_token(pam_handle_t *pamh, char *ftc_accesstoken, char *username, char *token, char **authtoken)
{
	// Validate input
	if( username == NULL || ftc_accesstoken == NULL || strlen(username) <= 0 || strlen(ftc_accesstoken) <= 0 )
	{
		pam_syslog(pamh, LOG_ERR, "Invalid username or access token supplied to ftm_validate_token");
		return PAM_AUTHINFO_UNAVAIL;
	}

	int numerical_token = 0;
	if( token != NULL && strlen(token) > 0 )
	{
		numerical_token = atoi(token);
	}

	// Setup CURL
	struct curl_slist* headers = NULL;
	struct MemoryStruct chunk;
	long http_code = 0;
	CURLcode res;
	CURL *curl;
	int i = 0;

	curl = curl_easy_init();
	if( curl )
	{
		// Create struct for response data
		chunk.memory = malloc(1);
		chunk.size = 0;

		// Create post data
		char postdata[512];
		if( numerical_token > 0 )
		{
			// Token supplied, validate the token
			if( (strlen(username) + strlen(token)) > 400 || sprintf(postdata, R"anydelim( {"username": "%s", "token": "%d"} )anydelim", username, numerical_token) < 0 )
			{
				pam_syslog(pamh, LOG_ERR, "Unable to construct POST payload");
				return PAM_AUTHINFO_UNAVAIL;
			}
		}
		else
		{
			// No token supplied, perform a push request and return the id
			if( strlen(username) > 400 || sprintf(postdata, R"anydelim( {"username": "%s"} )anydelim", username) < 0 )
			{
				pam_syslog(pamh, LOG_ERR, "Unable to construct POST payload");
				return PAM_AUTHINFO_UNAVAIL;
			}
		}

		// Create auth header
		char access_header[512];
		if( strlen(ftc_accesstoken) > 480 || sprintf(access_header, "Authorization: Bearer %s", ftc_accesstoken) < 0 )
		{
			pam_syslog(pamh, LOG_ERR, "Unable to construct POST headers");
			return PAM_AUTHINFO_UNAVAIL;
		}

		// Configure Headers
		headers = curl_slist_append(headers, "Content-Type: application/json");
		headers = curl_slist_append(headers, access_header);

		// Set headers and request
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt(curl, CURLOPT_URL, FTC_API_AUTH_URL);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if( http_code >= 200 && http_code <= 299 && res == CURLE_OK )
		{
			// Check if we need to extract a token from the response body
			if( numerical_token == 0 )
			{
				// Find the start of the authid
				char *substr;
				substr = strstr(chunk.memory, "authid");
				if( substr != NULL )
				{
					// Find the length of the authid response
					int authid_len = 0;
					char *startstring = substr + 10;
					for( i=0; i<strlen(startstring); i++ )
					{
						if( startstring[i] == '"' ) break;
						authid_len++;
					}

					// Validate the length we have determined
					if( authid_len > 0 && authid_len < 1024 )
					{
						// Allocate memory for the new authid
						char *authid;
						authid = (char*)malloc(authid_len + 1);
						if( authid != NULL )
						{
							// Copy substring into memory
							strncpy(authid, startstring, authid_len);
							authid[authid_len] ='\0';

							pam_syslog(pamh, LOG_DEBUG, "FTC Push AuthID retrieved successfully %s", authid);
							authtoken[0] = authid;
						}
					}
				}
			}

			// A 200 response indicates that we have a valid token from the user
			// https://docs.fortinet.com/document/fortitoken-cloud/latest/rest-api/191897/post
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			free(chunk.memory);

			return PAM_SUCCESS;
		}
		else if( http_code == 400 && res == CURLE_OK )
		{
			// Possible the user isn't assigned to this app
			if( strstr(chunk.memory, "does not exist") != NULL )
			{
				// Clean up previous request
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(chunk.memory);

				return PAM_USER_UNKNOWN;
			}
		}

		// A failure response here indicates that we have failed to validate the user token
		// https://docs.fortinet.com/document/fortitoken-cloud/latest/rest-api/191897/post
		pam_syslog(pamh, LOG_ERR, "CURL Error; Response Code: %d, Error: %s", http_code, curl_easy_strerror(res));
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		free(chunk.memory);
		
		return PAM_AUTH_ERR;
	}

	pam_syslog(pamh, LOG_ERR, "Failed to initialise CURL");
	return PAM_AUTHINFO_UNAVAIL;
}

/*
 * Validate a PUSH notification by the authtoken returned
 */
int ftm_validate_push(pam_handle_t *pamh, char *ftc_accesstoken, char *authtoken)
{
	// Validate input
	if( authtoken == NULL || ftc_accesstoken == NULL || strlen(authtoken) <= 0 || strlen(ftc_accesstoken) <= 0 )
	{
		pam_syslog(pamh, LOG_ERR, "Invalid authtoken or access token supplied to ftm_validate_token");
		return PAM_AUTHINFO_UNAVAIL;
	}

	// Setup CURL
	struct curl_slist* headers = NULL;
	struct MemoryStruct chunk;
	long http_code = 0;
	CURLcode res;
	CURL *curl;

	curl = curl_easy_init();
	if( curl )
	{
		// Create struct for response data
		chunk.memory = malloc(1);
		chunk.size = 0;

		// Create get string
		char getrequest[512];
		if( strlen(authtoken) > 400 || sprintf(getrequest, "%s/%s", FTC_API_AUTH_URL, authtoken) < 0 )
		{
			pam_syslog(pamh, LOG_ERR, "Unable to construct GET request");
			return PAM_AUTHINFO_UNAVAIL;
		}

		// Create auth header
		char access_header[512];
		if( strlen(ftc_accesstoken) > 480 || sprintf(access_header, "Authorization: Bearer %s", ftc_accesstoken) < 0 )
		{
			pam_syslog(pamh, LOG_ERR, "Unable to construct POST headers");
			return PAM_AUTHINFO_UNAVAIL;
		}

		// Configure Headers
		headers = curl_slist_append(headers, "Content-Type: application/json");
		headers = curl_slist_append(headers, access_header);

		// Set headers and request
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_URL, getrequest);

		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if( http_code >= 200 && http_code <= 299 && res == CURLE_OK )
		{
			pam_syslog(pamh, LOG_DEBUG, "CURL Response: %s", chunk.memory);
			if( strstr(chunk.memory, "authenticated") != NULL )
			{
				// User accepted the push request
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(chunk.memory);

				return PAM_SUCCESS;
			}
		}

		// Failed response code or the response data was not authenticated
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		free(chunk.memory);
		
		return PAM_AUTH_ERR;
	}

	pam_syslog(pamh, LOG_ERR, "Failed to initialise CURL");
	return PAM_AUTHINFO_UNAVAIL;
}

/*
 * The pam_sm_setcred function is the service module's implementation of the pam_setcred(3) interface.
 * This function performs the task of altering the credentials of the user with respect to the corresponding authorization scheme. 
 * Generally, an authentication module may have access to more information about a user than their authentication token. 
 * This function is used to make such information available to the application. 
 * It should only be called after the user has been authenticated but before a session has been established.
 * https://linux.die.net/man/3/pam_sm_setcred
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/*
 * The pam_sm_authenticate function is the service module's implementation of the pam_authenticate(3) interface.
 * This function performs the task of authenticating the user.
 * https://linux.die.net/man/3/pam_sm_authenticate
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
	int retval = PAM_SUCCESS;
	char ftc_appsecret[256];
	char ftc_apptoken[256];
	char user_suffix[256];
	int max_attempts = 3;
	int enable_push = 1;
	char *username;
	int i;

	// Retrieve app settings
	for( i = 0; i < argc; i++ )
	{
		if( strlen(argv[i]) >= 256 ) continue;
		if( strncmp(argv[i], "ftc_id=", 7) == 0 )
		{
			strncpy(ftc_apptoken, argv[i]+7, 256);
		}
		else if( strncmp(argv[i], "ftc_secret=", 11) == 0 )
		{
			strncpy(ftc_appsecret, argv[i]+11, 256);
		}
		else if( strncmp(argv[i], "user_suffix=", 12) == 0 )
		{
			strncpy(user_suffix, argv[i]+12, 256);
		}
		else if( strncmp(argv[i], "enable_push=no", 14) == 0 )
		{
			enable_push = 0;
		}
		else if( strncmp(argv[i], "max_attempts=", 13) )
		{
			int tempint = 0;
			char temp[256];

			// Attempt conversion of substring to int
			strncpy(temp, argv[i]+13, 256);
			tempint = atoi(temp);

			// Only allow setting if within the range 1 - 10
			if( tempint > 0 && tempint < 11 ) max_attempts = tempint;
		}
	}

	// Check app settings
	if( strlen(ftc_appsecret) == 0 || strlen(ftc_apptoken) == 0 )
	{
		pam_syslog(pamh, LOG_ERR, "Unable to initialise due to invalid or missing ftc_id or ftc_secret arguments");
		return PAM_CRED_INSUFFICIENT;
	}

	// Find the username of the user authenticating and apply suffix if appropriate
	const char *usertemp;
	if( (retval = pam_get_user(pamh, &usertemp, "login: ")) != PAM_SUCCESS )
	{
		return retval;
	}

	int user_length = strlen(usertemp) + strlen(user_suffix);
	username = (char*)malloc(user_length + 1);
	if( username == NULL )
	{
		pam_syslog(pamh, LOG_ERR, "Unable to allocate memory for username buffer");
		return PAM_CRED_INSUFFICIENT;
	}

	sprintf(username, "%s%s", usertemp, user_suffix);
	pam_syslog(pamh, LOG_DEBUG, "Got username: %s", username);

	// cURL Init
	curl_global_init(CURL_GLOBAL_ALL);
	pam_syslog(pamh, LOG_INFO, "Attempting FortiToken authentication for user %s", username);

	// Exchange apptoken for bearer token
	char *ftc_bearertoken = NULL;
	if( (ftc_bearertoken = ftm_get_access_token(pamh, ftc_apptoken, ftc_appsecret)) == NULL )
	{
		pam_syslog(pamh, LOG_ERR, "Unable to fetch bearer token from FTC cloud service");
		curl_global_cleanup();
		free(username);

		return PAM_CRED_INSUFFICIENT;
	}

	// Validate the user exists, and send a push notification (if enabled in FTC for the user)
	char *authtoken = NULL;
	if( enable_push == 1 && (retval = ftm_validate_token(pamh, ftc_bearertoken, username, NULL, &authtoken)) == PAM_USER_UNKNOWN )
	{
		// Attempt user creation
		pam_syslog(pamh, LOG_INFO, "Attempting to auto-create user in FTC Cloud Service", username);
		if( (retval = ftm_create_user(pamh, ftc_bearertoken, username)) != PAM_SUCCESS )
		{
			pam_syslog(pamh, LOG_INFO, "Auto-creation failed", username);
			if( flags & PAM_DISALLOW_NULL_AUTHTOK )
			{
				pam_syslog(pamh, LOG_INFO, "Denying %s as they do not exist in FTC and PAM_DISALLOW_NULL_AUTHTOK set", username);
				curl_global_cleanup();
				free(ftc_bearertoken);
				free(username);

				return PAM_AUTH_ERR;
			}
			else
			{
				pam_syslog(pamh, LOG_INFO, "Allowing %s as they do not exist in FTC and PAM_DISALLOW_NULL_AUTHTOK not set", username);
				curl_global_cleanup();
				free(ftc_bearertoken);
				free(username);

				return PAM_SUCCESS;
			}
		}
	}
	else if( enable_push == 1 && retval != PAM_SUCCESS )
	{
		pam_syslog(pamh, LOG_ERR, "Failed to request Push Notification for user %s", username);
	}

	// Setup Challenge-Response Authentication
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;
	struct pam_conv *conv;
	char *text;

	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	if( enable_push == 1 ) msg[0].msg = FTC_PROMPT_MSG_PUSH;
	else msg[0].msg = FTC_PROMPT_MSG;
	pmsg[0] = &msg[0];
	resp = NULL;

	// Get pam conversation handle
	if( (retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv)) != PAM_SUCCESS )
	{
		pam_syslog(pamh, LOG_ERR, "Failed obtaining pam conversation handle %d", retval);
		if( authtoken != NULL ) free(authtoken);
		curl_global_cleanup();
		free(ftc_bearertoken);
		free(username);
		return retval;
	}

	for( i = 0; i < max_attempts; i++ )
	{
		// Send pam message
		if( (retval = conv->conv(1, (const struct pam_message **)pmsg, &resp, conv->appdata_ptr)) != PAM_SUCCESS )
		{
			pam_syslog(pamh, LOG_ERR, "Failed sending message to pam (%d) - Usually this means ChallengeResponseAuthentication is disabled in sshd", retval);
			if( authtoken != NULL ) free(authtoken);
			curl_global_cleanup();
			free(ftc_bearertoken);
			free(username);
			return retval;
		}

		// Get user response
		if( resp )
		{
			// Attempt to validate input text, if present
			if( resp[0].resp != NULL )
			{
				text = resp[0].resp;
				resp[0].resp = NULL;
				if( strlen(text) > 0 )
				{
					// User entered something into the challenge prompt, validate input
					if( (retval = ftm_validate_token(pamh, ftc_bearertoken, username, text, NULL)) == PAM_SUCCESS )
					{
						pam_syslog(pamh, LOG_INFO, "FTC Token authentication succeeded for username %s", username);
						if( authtoken != NULL ) free(authtoken);
						curl_global_cleanup();
						free(ftc_bearertoken);
						free(username);
						free(text);

						return PAM_SUCCESS;
					}
					else if( retval == PAM_USER_UNKNOWN )
					{
						// Attempt user creation
						pam_syslog(pamh, LOG_INFO, "Attempting to auto-create user in FTC Cloud Service", username);
						if( (retval = ftm_create_user(pamh, ftc_bearertoken, username)) != PAM_SUCCESS )
						{
							pam_syslog(pamh, LOG_INFO, "Auto-creation failed", username);
							if( flags & PAM_DISALLOW_NULL_AUTHTOK )
							{
								pam_syslog(pamh, LOG_INFO, "Denying %s as they do not exist in FTC and PAM_DISALLOW_NULL_AUTHTOK set", username);
								curl_global_cleanup();
								free(ftc_bearertoken);
								free(username);

								return PAM_AUTH_ERR;
							}
							else
							{
								pam_syslog(pamh, LOG_INFO, "Allowing %s as they do not exist in FTC and PAM_DISALLOW_NULL_AUTHTOK not set", username);
								curl_global_cleanup();
								free(ftc_bearertoken);
								free(username);

								return PAM_SUCCESS;
							}
						}
					}

					// Validation failed
					pam_syslog(pamh, LOG_INFO, "Authentication failed %d (attempt %d of %d)", retval, i+1, max_attempts);
					free(username);
					free(text);
					continue;
				}

				// Free response object
				if( text != NULL ) free(text);
				text = NULL;
			}

			// No input text from user, validate push notification
			pam_syslog(pamh, LOG_DEBUG, "User did not respond, validating FTM Push");
			if( (retval = ftm_validate_push(pamh, ftc_bearertoken, authtoken)) == PAM_SUCCESS )
			{
				pam_syslog(pamh, LOG_INFO, "FTC PUSH authentication succeeded for username %s", username);
				if( authtoken != NULL ) free(authtoken);
				curl_global_cleanup();
				free(ftc_bearertoken);
				free(username);
				return retval;
			}

			// Log failed auth attempt
			pam_syslog(pamh, LOG_INFO, "Authentication failed %d (attempt %d of %d)", retval, i+1, max_attempts);
		}
		else
		{
			// Invalid conversation response
			pam_syslog(pamh, LOG_INFO, "Authentication failed - PAM conversation error");
			if( authtoken != NULL ) free(authtoken);
			if( text != NULL ) free(text);
			curl_global_cleanup();
			free(ftc_bearertoken);
			free(username);

			return PAM_CONV_ERR;
		}
	}

	// Authentication tries exceeded
	pam_syslog(pamh, LOG_INFO, "Authentication attempts exceeded %d retries for username %s", max_attempts, username);
	curl_global_cleanup();
	free(ftc_bearertoken);
	free(username);

	return PAM_MAXTRIES;
}

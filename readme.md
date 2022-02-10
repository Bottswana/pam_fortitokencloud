# pam_fortitokencloud

An experimental PAM module that attempts to add 2FA support to PAM using the FortiNet FortiToken-Cloud service

### Not working

Push notifications. The FortiToken Cloud API is just not working as documented. When using a "Generic App" the push notifications are recieved but the response from the user never makes it to the cloud portal (At least in iOS)
For now, this code path is commented until FortiNet fix this issue.

### Example PAM Config

Example PAM config, for example, in `/etc/pam.d/sshd`

```
auth required pam_fortitokencloud.so user_suffix=@domainname.com ftc_id=appid ftc_secret=appsecret
```


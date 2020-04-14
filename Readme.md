# Authentifi
## Overview
Authentifi is a pre-configured spring security based module which leverages JWT and AES to ensure secure and stateless authentication and authorization flow.

## Getting started
### Installation
```
<dependency>
    <groupId>dev.sanda</groupId>
	    <artifactId>authentifi</artifactId>
    <version>0.0.2</version>
</dependency>
```
#### Configuration
Implement the [`AuthenticationServerConfiguration`](https://github.com/sanda-dev/authentifi/blob/master/src/main/java/dev/sanda/authentifi/config/AuthenticationServerConfiguration.java) interface, and make sure it's wired into the application context (`@Component`, etc.).
#### Sign In
Authentifi exposes the `/auth/signin` endpoint to POST requests consisting of a `username`, `password` and (optional - defaults to false) `rememberMe` flag. The method has no direct return value, but instead sets an `access_token` cookie, as well as a `refresh_token` cookie if the `rememberMe` flag was set to `true`. Both cookies consist of an AES-256 bit encrypted JWT token. The cookies are both `httpOnly`, and have the same expiration as their contained JWT values.

#### Subsequent requests
After successful authentication, Authentifi will sets the spring `SecurityContext` with each request in accordance with the accompanying`access_token`. If the access token is absent or expired, the `refresh_token` (if present) will automatically be used to issue a new set of tokens, and the `SecurityContext` is set in accordance with the new `access_token`.
rypted JWT token. The cookies are both `httpOnly`, and have the same expiration as their contained JWT values.



# Back-end
This is an API used by the <a href="https://github.com/character-navigator/frontend">front-end service<a/> for authenticating users, hosting ePub files and managing the user's reading progress.

## Note
To authenticate users properly, the environment variable "SigningSecret" (used when signing the authentication token) must be set to a 32 character secret.

## Project Setup
To run the program, execute the following command using the .NET SDK.
```bash
dotnet run
```

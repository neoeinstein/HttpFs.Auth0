namespace HttpFs.Auth0

open System
open Hopac
open HttpFs.Client

/// Various types used for Auth0.
[<AutoOpen>]
module Types =

  //# Wrapped types

  /// Identifies a client in an OAuth2 workflow
  type ClientId = ClientId of string

  /// Operations for interacting with `ClientId`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module ClientId =
    val create:   str:string   -> ClientId
    val toString: cid:ClientId -> string

  /// Token used for interacting with the Auth0 Management API
  type AccessToken

  /// Operations for interacting with `AccessToken`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module AccessToken =
    val create:   str:string     -> AccessToken
    val toString: at:AccessToken -> string

  /// Long-lived token which can be used in place of a username/password
  /// for peristent access.
  type RefreshToken

  /// Operations for interacting with `RefreshToken`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module RefreshToken =
    val create:   str:string      -> RefreshToken
    val toString: rt:RefreshToken -> string

  //# JWT Tokens

  /// The payload portion of a JWT Token. This is a partial implementation
  /// which handles the basic claims provided in Auth0 ID Tokens.
  type JwtTokenPayload =
    { /// The "iss" (issuer) claim identifies the principal that issued the
      /// JWT.  The processing of this claim is generally application specific.
      /// The "iss" value is a case-sensitive string containing a StringOrURI
      /// value.
      Issuer        : string

      /// The "sub" (subject) claim identifies the principal that is the
      /// subject of the JWT.  The claims in a JWT are normally statements
      /// about the subject.  The subject value MUST either be scoped to be
      /// locally unique in the context of the issuer or be globally unique.
      /// The processing of this claim is generally application specific.  The
      /// "sub" value is a case-sensitive string containing a StringOrURI
      /// value.  Use of this claim is OPTIONAL.
      Subject        : string

      /// The "aud" (audience) claim identifies the recipients that the JWT is
      /// intended for.  Each principal intended to process the JWT MUST
      /// identify itself with a value in the audience claim.  If the principal
      /// processing the claim does not identify itself with a value in the
      /// "aud" claim when this claim is present, then the JWT MUST be
      /// rejected.  In the general case, the "aud" value is an array of case-
      /// sensitive strings, each containing a StringOrURI value.  In the
      /// special case when the JWT has one audience, the "aud" value MAY be a
      /// single case-sensitive string containing a StringOrURI value.  The
      /// interpretation of audience values is generally application specific.
      Audience       : string

      /// The "exp" (expiration time) claim identifies the expiration time on
      /// or after which the JWT MUST NOT be accepted for processing.  The
      /// processing of the "exp" claim requires that the current date/time
      /// MUST be before the expiration date/time listed in the "exp" claim.
      /// Implementers MAY provide for some small leeway, usually no more than
      /// a few minutes, to account for clock skew.  Its value MUST be a number
      /// containing a NumericDate value.
      ExpirationTime : int64 option

      /// The "iat" (issued at) claim identifies the time at which the JWT was
      /// issued.  This claim can be used to determine the age of the JWT.  Its
      /// value MUST be a number containing a NumericDate value.
      IssuedAt       : int64 option
    }

  /// Operations for interacting with `JwtTokenPayload`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module JwtTokenPayload =
    val inline issuer:         jwtPayload:JwtTokenPayload -> string
    val inline subject:        jwtPayload:JwtTokenPayload -> string
    val inline audience:       jwtPayload:JwtTokenPayload -> string
    val inline expirationTime: jwtPayload:JwtTokenPayload -> int64 option
    val inline issuedAt:       jwtPayload:JwtTokenPayload -> int64 option

  /// Identifies the type of token
  type TokenType

  /// Operations for interacting with `TokenType`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module TokenType =
    val create:   str:string   -> TokenType
    val toString: tt:TokenType -> string

    val bearer: TokenType
    val basic:  TokenType
    val digest: TokenType

  /// JSON Web Token (JWT) is a compact, URL-safe means of representing
  /// claims to be transferred between two parties.  The claims in a JWT
  /// are encoded as a JSON object that is used as the payload of a JSON
  /// Web Signature (JWS) structure or as the plaintext of a JSON Web
  /// Encryption (JWE) structure, enabling the claims to be digitally
  /// signed or integrity protected with a Message Authentication Code
  /// (MAC) and/or encrypted.
  type JwtToken

  /// Operations for interacting with `JwtToken`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module JwtToken =
    val create:   str:string   -> JwtToken
    val toString: jwt:JwtToken -> string

    /// Builds the string required for an HTTP `Authorization` header value.
    val toHttpAuthorizationHeaderString: tt:TokenType -> jwt:JwtToken -> string

    /// Attempts to decode the payload of the JSON Web Token. This may fail
    /// if the token is malformed or a JWE token. No validation is done on the
    /// payload's validity, and the signature of a JWS token is not checked.
    val tryDecodePayload: jwt:JwtToken -> Choice<JwtTokenPayload,string>

  //# Auth0 Interaction

  /// A structure identifying a host conforming to the
  /// [Auth0 Authentication API](https://auth0.com/docs/api/authentication)
  /// as well as the client ID to use to authenticate and receive an
  /// identifying token.
  type ClientParams =
    { /// The Authentication API host
      AuthenticationHost : string

      /// The ID of the client which requires authentication
      ClientId           : ClientId
    }

  /// Represents the authentication information returned after authenticating
  /// with an Auth0 authentication host.
  type Auth0Token

  /// Operations for interacting with `Auth0TOken`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module Auth0Token =
    val tokenType:    a0token:Auth0Token -> TokenType
    val idToken:      a0token:Auth0Token -> JwtToken
    val accessToken:  a0token:Auth0Token -> AccessToken option
    val refreshToken: a0token:Auth0Token -> RefreshToken option

    /// Builds the string required for an HTTP `Authorization` header value.
    val toHttpAuthorizationHeaderString: a0token:Auth0Token -> string

  /// Credentials used to authenticate with an Auth0 Authentication API
  type Auth0Credentials =
    /// A username and password as well as the connection which acts
    /// as an identity provider.
    | UsernamePassword of connection:string * username:string * password:string

    /// A JWT token used to identify the requestor.
    | IdToken          of jwt:JwtToken

    /// A long-lived token uses as a substitute for username/password
    /// authentication.
    | RefreshToken     of rt:RefreshToken

  /// Represents a failed attempt to interact with an Auth0 API.
  type Auth0ApiFailure =
    /// Indicates an error reported by the Auth0 API.
    | ApiError             of err:Auth0ApiError

    /// Indicates that there was an error deserializing the response.
    | DeserializationError of err:string

    /// Indicates that an unhandled exception was thrown while trying to
    /// get a response from the API.
    | ApiException         of exn

    /// Indicates that the attempt to interact with the API timed out.
    | OperationTimedOut

    /// Indicates that no interaction with the API could occur due to a lack
    /// of credentials.
    | NoCredentials

  /// Represents an error reported by the Auth0 API.
  and Auth0ApiError =
    { /// A string representing the class of API error.
      ErrorType   : string

      /// A longer description describing the particular API error.
      Description : string
    }

/// Interactions with the Auth0 Authentication API.
module Authentication =

  /// Represents the result of attempting to authenticate with the API.
  type AuthenticationResult =
    /// Indicates a successful authentication attempt, resulting in a token.
    | AuthOk   of a0token:Auth0Token

    /// Indicates a failed authentication attempt.
    | AuthFail of failure:Auth0ApiFailure

  /// Operations for interacting with `AuthenticationResult`.
  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module AuthenticationResult =
    val toChoice: ar:AuthenticationResult -> Choice<Auth0Token,Auth0ApiFailure>

  /// Constructs an authentication request against the authentication host's
  /// active authentication endpoint using the specified credentials.
  val createRequest: cp:ClientParams -> ac:Auth0Credentials -> Request

  /// Asynchronously processes an authentication request and attempts to
  /// interpret the response as an `AuthenticationResult`.
  val tryAuthenticate: req:Request -> Alt<AuthenticationResult>

  /// Asynchronously constructs and processes an authentication response,
  /// attempting to obtain authentication credentials from an asynchronous
  /// source which can be used to ensure the requested URI and
  /// client parameters match a predetermined whitelist.
  val tryAuthenticateFromSource:
         ats : (Uri -> ClientParams -> #Job<Auth0Credentials option>)
      -> uri : Uri
      -> cp  : ClientParams
      -> Alt<AuthenticationResult>

/// Interactions with requests.
module Client =
  /// Adds an Auth0 token to the request in an `Authorization` header.
  val addAuth0TokenHeader: a0token:Auth0Token -> req:Request -> Request

  /// Attempts to retrieve an Auth0 token from an asynchronous source, adding it
  /// to the request if available.
  val addAuth0TokenHeaderFromSource:
         ats : (Uri -> ClientParams -> #Job<Auth0Token option>)
      -> cp  : ClientParams
      -> req : Request
      -> Alt<Request>


  /// Attempts retrieve an Auth0 token from an asynchronous source, adding it
  /// to the request if available and then processes the request.
  val tryGetResponseWithAuthSource:
         ats : (Uri -> ClientParams -> #Job<Auth0Token option>)
      -> cp  : ClientParams
      -> req : Request
      -> Alt<Choice<Response,exn>>

  /// Handles a response. If the response is `401 Unauthorized`, attempts to
  /// retrieve an Auth0 token and if available, retries the request with the
  /// token added to the request. The result of the retry is returned. In all
  /// other cases, the response is passed through unaltered.
  val tryWithRetryOnAuthRequired:
         ats    : (Uri -> ClientParams -> #Job<Auth0Token option>)
      -> req    : Request
      -> respCJ : #Job<Choice<Response,exn>>
      -> Alt<Choice<Response,exn>>

  /// Attempts to process a request, then if the response is `401 Unauthorized`,
  /// retries the request after retrieving an Auth0 token from an asynchronous source.
  /// The result of the retried response or any other initial response is returned.
  val tryGetResponseWithRetryOnAuthRequired:
         ats : (Uri -> ClientParams -> #Job<Auth0Token option>)
      -> req : Request
      -> Alt<Choice<Response,exn>>

/// Represents the parameters used for determining the validity of cached entries.
type CacheExpirationParameters

/// Operations for interacting with `CacheExpirationParameters`.
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module CacheExpirationParameters =
  /// Creates a `CacheExpirationParameters` value with a custom implementation
  /// for obtaining the current UNIX timestamp. Also specifies the default max age
  /// in seconds to use for any token which doesn't specify its own expiration as
  /// well as the how long to cache timeouts and API failures.
  val create:
         getNow          : Job<int64>
      -> defaultMaxAge   : int64
      -> maxAgeOnTimeout : int64
      -> MaxAgeOnFailure : int64
      -> CacheExpirationParameters

  /// Creates a `CacheExpirationParameters` value which specifies the default max age
  /// in seconds to use for any token which doesn't specify its own expiration as
  /// well as the how long to cache timeouts and API failures.
  val create':
         defaultMaxAge   : int64
      -> maxAgeOnTimeout : int64
      -> MaxAgeOnFailure : int64
      -> CacheExpirationParameters

/// Represents a cache associating Auth0 authentication tokens with a `ClientParams`
type TokenCache

/// Operations for interacting with a `TokenCache`.
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module TokenCache =
  /// Creates a new token cache.
  val create: unit -> Job<TokenCache>

  /// Adds a token to the cache with the specified expiration time (in UNIX time).
  val putToken:
         tc  : TokenCache
      -> cp  : ClientParams
      -> at  : Auth0Token
      -> exp : int64
      -> Alt<unit>

  /// Processes an authentication result, caching the value for a particular client
  /// using the cache expiration parameters provided.
  val putAuthenticationResult:
         cep : CacheExpirationParameters
      -> tc  : TokenCache
      -> cp  : ClientParams
      -> ar  : Authentication.AuthenticationResult
      -> Alt<unit>

  /// Attempts to get an Auth0 authentication result from the cache. Does not check the expiration of the returned value.
  val tryGetEntry:
         tc : TokenCache
      -> cp : ClientParams
      -> Alt<Choice<Auth0Token,Auth0ApiFailure> option>

  /// Attempts to get an unexpired Auth0 authentication token from the cache.
  val tryGetToken:
         cep : CacheExpirationParameters
      -> tc  : TokenCache
      -> cp  : ClientParams
      -> Alt<Auth0Token option>

  /// Attempts to get an unexpired Auth0 authentication token from the cache. If the
  /// token is expired or doesn't exist in the cache, gets an authentication result
  /// and adds it to the cache. The token provided by this authentication result is
  /// then returned. The token is added in such a way that if there are multiple
  /// concurrent requests for the same token, they will await the same response.
  val tryGetTokenWithFill:
         cep    : CacheExpirationParameters
      -> cp2arJ : (ClientParams -> #Job<Authentication.AuthenticationResult>)
      -> tc     : TokenCache
      -> cp     : ClientParams
      -> Alt<Auth0Token option>

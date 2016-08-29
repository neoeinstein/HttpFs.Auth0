namespace HttpFs.Auth0

open Chiron
open Hopac
open Hopac.Plus.Collections
open HttpFs.Client
#if LOGGING
open HttpFs.Logging
open HttpFs.Logging.Message
#endif

module MimeTypes =
  let [<Literal>] JsonString = "application/json"
  let Json = ContentType.parse JsonString |> Option.get

module Json =
  let inline writeMixin (a : ^a) =
    (^a : (static member ToJson: ^a -> Json<unit>) a)

  let inline readMixin json =
    (^a : (static member FromJson: ^a -> Json<'a>) Unchecked.defaultof<_>) json

[<AutoOpen>]
module Types =
  type ClientId = ClientId of string with
    override x.ToString () =
      match x with ClientId cid -> cid

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module ClientId =
    let create cid = ClientId cid
    let toString (ClientId cid) = cid

  type AccessToken = AccessToken of string with
    override x.ToString () =
      match x with AccessToken at -> at

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module AccessToken =
    let create at = AccessToken at
    let toString (AccessToken at) = at

  type RefreshToken = RefreshToken of string with
    override x.ToString () =
      match x with RefreshToken rt -> rt

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module RefreshToken =
    let create rt = RefreshToken rt
    let toString (RefreshToken rt) = rt

  type JwtTokenPayload =
    { Issuer : string
      Subject : string
      Audience : string
      ExpirationTime : int64 option
      IssuedAt : int64 option
    }
    static member FromJson (_ : JwtTokenPayload) =
      let (<!>) = Chiron.Operators.(<!>)
      let (<*>) = Chiron.Operators.(<*>)
      let mk i s a e v =
        { Issuer = i; Subject = s; Audience = a
          ExpirationTime = e; IssuedAt = v
        }
      mk
      <!> Json.read "iss"
      <*> Json.read "sub"
      <*> Json.read "aud"
      <*> Json.readOrDefault "exp" None
      <*> Json.readOrDefault "iat" None

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module JwtTokenPayload =
    let inline issuer { Issuer = iss } = iss
    let inline subject { Subject = sub } = sub
    let inline audience { Audience = aud } = aud
    let inline expirationTime { ExpirationTime = exp } = exp
    let inline issuedAt { IssuedAt = iat } = iat

  type TokenType = TokenType of string with
    override x.ToString () =
      match x with TokenType tt -> tt

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module TokenType =
    let toString (TokenType t) = t

    let bearer = TokenType "bearer"
    let basic = TokenType "basic"
    let digest = TokenType "digest"

    let create str =
      match str with
      | "bearer" -> bearer
      | "basic" -> basic
      | "digest" -> digest
      | _ -> TokenType str

  type JwtToken = JwtToken of string with
    override x.ToString () =
      match x with JwtToken jwt -> jwt

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module JwtToken =
    let create jwt = JwtToken jwt
    let toString (JwtToken jwt) = jwt

    let toHttpAuthorizationHeaderString (TokenType tt) (JwtToken jwt) =
      tt + " " + jwt

    let tryDecodePayload (JwtToken token) =
      let parts = token |> String.split '.'
      match parts with
      | [ payload ] | [ _; payload; _ ] ->
        let paddedPayload =
          match String.length payload % 4 with
          | 0 -> Choice1Of2 payload
          | 1 -> Choice2Of2 "Absurd: payload length % 4 was 1"
          | 2 -> Choice1Of2 ^ payload + "=="
          | 3 -> Choice1Of2 ^ payload + "="
          | _ -> Choice2Of2 "Absurd: payload length % 4 was not 0, 2, or 3"
        flip Choice.bind paddedPayload ^ fun p ->
          try
            System.Convert.FromBase64String p
            |> System.Text.Encoding.UTF8.GetString
            |> Json.tryParse
            |> Choice.bind (Json.tryDeserialize : _ -> Choice<JwtTokenPayload,_>)
          with ex -> Choice2Of2 ^ string ex
      | _ -> Choice2Of2 "Invalid token"

    let [<Literal>] GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

  type ClientParams =
    { AuthenticationHost : string
      ClientId : ClientId
    }
    override x.ToString () =
      sprintf "{ AuthenticationHost = \"%s\"; ClientId = \"%O\" }" x.AuthenticationHost x.ClientId

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module ClientParams =
    let activeAuthUrl { AuthenticationHost = h } =
      System.Uri (sprintf "https://%s/oauth/ro" h, System.UriKind.Absolute)

  type Auth0Token =
    { TokenType : TokenType
      IdToken : JwtToken
      AccessToken : AccessToken option
      RefreshToken : RefreshToken option
    }
    static member FromJson (_ : Auth0Token) =
      let (<!>) = Chiron.Operators.(<!>)
      let (<*>) = Chiron.Operators.(<*>)
      let mk i a r t =
        { IdToken = JwtToken i
          AccessToken = Option.map AccessToken a
          RefreshToken = Option.map RefreshToken r
          TokenType = TokenType.create t
        }
      mk
      <!> Json.read "id_token"
      <*> Json.readOrDefault "access_token" None
      <*> Json.readOrDefault "refresh_token" None
      <*> Json.read "token_type"

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module Auth0Token =
    let tokenType { TokenType = tt } = tt
    let idToken { IdToken = jwt } = jwt
    let accessToken { AccessToken = at } = at
    let refreshToken { RefreshToken = rt } = rt
    let toHttpAuthorizationHeaderString { TokenType = tt; IdToken = jwt } =
      JwtToken.toHttpAuthorizationHeaderString tt jwt

  type Auth0Credentials =
    | UsernamePassword of connection:string * username:string * password:string
    | IdToken of jwt:JwtToken
    | RefreshToken of rt:RefreshToken
    static member ToJson (x: Auth0Credentials) =
      let ( *>) = Chiron.Operators.( *>)
      match x with
      | UsernamePassword (c,u,p) ->
        Json.write "connection" c
        *> Json.write "username" u
        *> Json.write "password" p
        *> Json.write "grant_type" "password"
      | IdToken t ->
        Json.write "id_token" (JwtToken.toString t)
        *> Json.write "grant_type" JwtToken.GrantType
      | RefreshToken t ->
        Json.write "refresh_token" (RefreshToken.toString t)
        *> Json.write "grant_type" "refresh_token"

  type Auth0ApiFailure =
    | ApiError of err:Auth0ApiError
    | DeserializationError of err:string
    | ApiException of exn
    | OperationTimedOut
    | NoCredentials
  and Auth0ApiError =
    { ErrorType : string
      Description : string
    }
    static member FromJson (_ : Auth0ApiError) =
      let (<!>) = Chiron.Operators.(<!>)
      let (<*>) = Chiron.Operators.(<*>)
      let mk e d =
        { ErrorType = e
          Description = d
        }
      mk
      <!> Json.read "error"
      <*> Json.read "error_description"

[<AutoOpen>]
module Util =
  let (|HttpStatus|_|) status (resp : Response) =
    if resp.statusCode = status then
      Some ()
    else
      None

module Logging =
  type SW = System.Diagnostics.Stopwatch
  let TicksPerUs = SW.Frequency / 1000000L

#if LOGGING
  let timeJob (doLog : Message -> unit) (xJ : Job<'x>) =  job {
    let sw = SW.StartNew()
    let! x = xJ
    doLog ^ gauge (sw.ElapsedTicks / TicksPerUs) "µs"
    return x
  }
#else
  let timeJob _ xJ = xJ
#endif

module Authentication =
#if LOGGING
  let logger = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication" |]
  let respHostLogger (uri : System.Uri) = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "responseTime"; String.replace "." "_" uri.Host |]
  let respPathLogger (uri : System.Uri) = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "responseTime"; String.replace "." "_" uri.Host; String.replace "." "_" uri.AbsolutePath |]
#endif

  type AuthenticationResult =
    | AuthOk of a0token:Auth0Token
    | AuthFail of failure:Auth0ApiFailure
    static member FromJson (_ : AuthenticationResult) =
      let (<!>) = Chiron.Operators.(<!>)
      let mk (idToken : string option) =
        match idToken with
        | Some _ ->
          AuthOk <!> Json.readMixin
        | None ->
          (AuthFail << ApiError) <!> Json.readMixin
      Json.bind (Json.read "id_token") mk

  [<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
  module AuthenticationResult =
    let toChoice ar =
      match ar with
      | AuthOk t -> Choice1Of2 t
      | AuthFail f -> Choice2Of2 f

  type AuthRequestData =
    { ClientId : ClientId
      Credentials : Auth0Credentials
    }
    static member ToJson (x : AuthRequestData) =
      let ( *>) = Chiron.Operators.( *>)
      Json.write "client_id" (ClientId.toString x.ClientId)
      *> Json.writeMixin x.Credentials
      *> Json.write "scope" "openid"

  let [<Literal>] HttpFsAuth0UserAgent =
    "HttpFs.Auth0 v"
#if INTERACTIVE
    + "F# Interactive"
#else
    + System.AssemblyVersionInformation.InformationalVersion
#endif

  let createRequest (cp : ClientParams) a0creds =
    let a0reqBody : AuthRequestData =
      { ClientId = cp.ClientId
        Credentials = a0creds
      }
    Request.create Post ^ ClientParams.activeAuthUrl cp
    |> Request.setHeader ^ ContentType MimeTypes.Json
    |> Request.setHeader ^ UserAgent HttpFsAuth0UserAgent
    |> Request.setHeader ^ Accept MimeTypes.JsonString
    |> Request.keepAlive false
    |> Request.bodyString (a0reqBody |> Json.serialize |> Json.format)

  let extractAuthResult (resp : Response) : Job<AuthenticationResult> = job {
#if LOGGING
    event Verbose "Reading authentication response"
    |> logger.logSimple
#endif

    let! bStrC = Response.readBodyAsString resp |> Job.catch
    return
      match bStrC with
      | Choice1Of2 bStr ->
#if LOGGING
        event Verbose "Read authentication response"
        |> setField "length" ^ String.length bStr
        |> logger.logSimple
#endif

        let (arC : Choice<AuthenticationResult,string>) =
          Json.tryParse bStr
          |> Choice.bind Json.tryDeserialize
        match arC with
        | Choice1Of2 ar ->
#if LOGGING
          logger.log Debug ^ fun _ ->
            match ar with
            | AuthOk _ ->
              event Debug "Successfully decoded authentication response"
            | AuthFail f ->
              event Warn "Authentication API reported an error during authentication"
              |> setField "error" f
#endif

          ar
        | Choice2Of2 err ->
#if LOGGING
          event Warn "Error while trying to deserialize authentication response"
          |> setField "error" err
          |> logger.logSimple
#endif

          AuthFail ^ DeserializationError err
      | Choice2Of2 ex ->
#if LOGGING
        event Warn "Error while trying to read authentication response"
        |> addExn ex
        |> logger.logSimple
#endif

        AuthFail ^ Auth0ApiFailure.ApiException ex
  }

  let choiceJobMap (x2zJ : 'x -> Job<'z>) (xyCJ : Job<Choice<'x,'y>>) : Job<Choice<'z,'y>> = job {
    let! xyC = xyCJ
    match xyC with
    | Choice1Of2 x ->
      let! z = x2zJ x
      return Choice1Of2 z
    | Choice2Of2 y ->
      return Choice2Of2 y
  }

  let logResponse (r : Response) : unit =
#if LOGGING
    let logLevel =
      match r.statusCode with
      | x when x >= 200 && x < 300 -> Debug
      | x when x >= 400 && x < 500 -> Warn
      | _ -> Info

    logger.log logLevel ^ fun ll ->
      event ll "Received response from authentication API {url} with status code {statusCode}"
      |> setField "statusCode" r.statusCode
      |> setField "url" r.responseUri
#else
    ()
#endif

  let logResponseTime uri msg =
#if LOGGING
    msg |> (respHostLogger uri).logSimple
    msg |> (respPathLogger uri).logSimple
#else
    ()
#endif

  let tryAuthenticate (req : Request) : Alt<AuthenticationResult> =
    Alt.prepare ^ job {
#if LOGGING
      event Debug "Attempting to authenticate with {url}"
      |> setField "url" req.url
      |> logger.logSimple
#endif

      let! rC =
        tryGetResponse req
        |> Logging.timeJob ^ logResponseTime req.url

      match rC with
      | Choice1Of2 r ->
        use r = r
        logResponse r
        let! ar = extractAuthResult r
        return Alt.always ar
      | Choice2Of2 ex ->
          match ex with
          | :? System.Net.WebException as exn when exn.Status = System.Net.WebExceptionStatus.Timeout ->
#if LOGGING
            event Info "Authentication request timed out after {timeout} milliseconds"
            |> setField "timeout" req.timeout
            |> logger.logSimple
#endif

            return Alt.always ^ AuthFail OperationTimedOut
          | ex ->
#if LOGGING
            event Info "Authentication request failed with an exception"
            |> addExn ex
            |> logger.logSimple
#endif

            return Alt.always ^ AuthFail ^ Auth0ApiFailure.ApiException ex
    }

#if LOGGING
  let credSourceLog = Log.createHiera [|"HttpFs"; "Auth0"; "Authorization"; "retrieveCredentials" |]
#endif

  let tryAuthenticateFromSource (u2cp2acOJ : System.Uri -> ClientParams -> #Job<Auth0Credentials option>) (uri : System.Uri) (cp : ClientParams) : Alt<_> =
    Alt.prepare ^ job {
#if LOGGING
      event Verbose "Attempting to retrieve credentials for {resourceUri} with {clientParams}"
      |> setField "resourceUri" uri
      |> setField "clientParams" cp
      |> logger.logSimple
#endif

      let! acO =
        asJob ^ u2cp2acOJ uri cp
        |> Logging.timeJob ^ fun msg ->
#if LOGGING
          msg
          |> setField "resourceUri" uri
          |> setField "clientParams" cp
          |> credSourceLog.logSimple
#else
          ()
#endif

      match acO with
      | Some ac ->
#if LOGGING
        event Debug "Found credentials for {resourceUri} with {clientParams}"
        |> setField "resourceUri" uri
        |> setField "clientParams" cp
        |> logger.logSimple
#endif

        return tryAuthenticate ^ createRequest cp ac
      | None ->
#if LOGGING
        event Info "Unable to find credentials for {resourceUri} with {clientParams}"
        |> setField "resourceUri" uri
        |> setField "clientParams" cp
        |> logger.logSimple
#endif

        return Alt.always ^ AuthFail NoCredentials
    }


module WwwAuthenticate =
  open System.Text.RegularExpressions

  let HeaderValueRegex =
    Regex
      ( @"(?<token>\w+)\s+(?:(?<key>\w+)=""(?<value>[^""]*)"",\s+)*(?<key>\w+)=""(?<value>[^""]*)"""
      , System.Text.RegularExpressions.RegexOptions.Compiled ||| System.Text.RegularExpressions.RegexOptions.IgnoreCase
      )

  let zipKvps (m : Match) =
    let cks : Capture array = Array.zeroCreate m.Groups.["key"].Captures.Count
    let cvs : Capture array = Array.zeroCreate m.Groups.["value"].Captures.Count
    m.Groups.["key"].Captures.CopyTo (cks, 0)
    m.Groups.["value"].Captures.CopyTo (cvs, 0)
    let ks = cks |> Array.map ^ fun c -> c.Value
    let vs = cvs |> Array.map ^ fun c -> c.Value
    let kvps = Array.zip ks vs
    Map.ofArray kvps

  let extractValues str =
    HeaderValueRegex.Matches str
    |> (fun mc ->
      let cms : Match array = Array.zeroCreate mc.Count
      mc.CopyTo (cms, 0)
      cms)
    |> Array.map ^ fun m -> String.toLowerInvariant m.Groups.["token"].Value, zipKvps m

  let tryFindChallengeType (TokenType ct) =
       Array.tryFind (fst >> String.equalsConstantTime ct)
    >> Option.map snd

module Auth0Client =
#if LOGGING
  let logger = Log.createHiera [| "HttpFs"; "Auth0"; "Auth0Client" |]
  let tokenSourceLog = Log.createHiera [| "HttpFs"; "Auth0"; "Auth0Client"; "retrieveToken" |]
  let respHostLogger (uri : System.Uri) = Log.createHiera [| "HttpFs"; "Auth0"; "Auth0Client"; "responseTime"; String.replace "." "_" uri.Host |]
  let respPathLogger (uri : System.Uri) = Log.createHiera [| "HttpFs"; "Auth0"; "Auth0Client"; "responseTime"; String.replace "." "_" uri.Host; String.replace "." "_" uri.AbsolutePath |]
#endif

  let splitKeyValuePair s =
    String.split '=' s |> function
    | [ k; v ] -> String.toLowerInvariant k, v
    | _ -> String.toLowerInvariant s, s

  let decomposeKeyValuePairs =
    String.split ' '
    >> List.map splitKeyValuePair
    >> Map.ofList

  let extractAuth0Params vars =
    let (<!>) = Option.Operators.(<!>)
    let (<*>) = Option.Operators.(<*>)

    fun r cid -> { AuthenticationHost = r; ClientId = cid }
    <!> Map.tryFind "realm" vars
    <*> ( Map.tryFind "scope" vars
          |> Option.map decomposeKeyValuePairs
          |> Option.bind ^ Map.tryFind "client_id"
          |> Option.map ClientId
        )

  let (|HasAuth0WwwAuthenticate|_|) (resp : Response) =
    Map.tryFind WWWAuthenticate resp.headers
    |> Option.bind (WwwAuthenticate.extractValues >> WwwAuthenticate.tryFindChallengeType TokenType.bearer)
    |> Option.bind extractAuth0Params

  let addAuth0TokenHeaderImpl =
    Auth0Token.toHttpAuthorizationHeaderString
    >> Authorization
    >> Request.setHeader

  let addAuth0TokenHeader t r =
    addAuth0TokenHeaderImpl t r

  let tryGetAuth0TokenWithLogging (u2cp2atOJ: System.Uri -> ClientParams -> #Job<Auth0Token option>) (uri : System.Uri) (cp : ClientParams) = job {
#if LOGGING
      event Verbose "Attempting to retrieve authentication token for {resourceUri} with {clientParams}"
      |> setField "resourceUri" uri
      |> setField "clientParams" cp
      |> logger.logSimple
#endif

      let! atO =
        asJob ^ u2cp2atOJ uri cp
        |> Logging.timeJob ^ fun msg ->
#if LOGGING
          msg
          |> setField "resourceUri" uri
          |> setField "clientParams" cp
          |> tokenSourceLog.logSimple
#else
          ()
#endif

#if LOGGING
      match atO with
      | Some _ ->
        event Debug "Found authentication token for {resourceUri} with {clientParams}"
        |> setField "resourceUri" uri
        |> setField "clientParams" cp
        |> logger.logSimple

      | None ->
        event Info "Unable to find credentials for {resourceUri} with {clientParams}"
        |> setField "resourceUri" uri
        |> setField "clientParams" cp
        |> logger.logSimple
#endif

      return atO
  }

  let addAuth0TokenHeaderFromSource (u2cp2atOJ: System.Uri -> ClientParams -> #Job<Auth0Token option>) cp req =
    Alt.prepare ^ job {
      let! atO = tryGetAuth0TokenWithLogging u2cp2atOJ req.url cp
      match atO with
      | Some at ->
        let setHeader = Request.setHeader ^ Authorization ^ Auth0Token.toHttpAuthorizationHeaderString at
        return Alt.always ^ setHeader req
      | None ->
        return Alt.always req
    }

  let logResponseTime uri msg =
#if LOGGING
    msg |> (respHostLogger uri).logSimple
    msg |> (respPathLogger uri).logSimple
#else
    ()
#endif

  let tryGetResponseWithAuthSource (u2cp2atOJ : System.Uri -> ClientParams -> #Job<Auth0Token option>) cp req =
    Alt.prepare ^ job {
      let! atO = tryGetAuth0TokenWithLogging u2cp2atOJ req.url cp
      let req1 = Option.fold (flip addAuth0TokenHeader) req atO
      let! respC =
        tryGetResponse req1
        |> Logging.timeJob ^ logResponseTime req.url
      return Alt.always respC
    }

  let tryWithRetryOnAuthRequired (u2cp2atOJ : System.Uri -> ClientParams -> #Job<Auth0Token option>) req (respCJ : #Job<_>) =
    Alt.prepare ^ job {
#if LOGGING
      event Verbose "Requesting resource {resourceUri}"
      |> setField "resourceUri" req.url
      |> logger.logSimple
#endif

      let! respC =
        asJob ^ respCJ
        |> Logging.timeJob ^ logResponseTime req.url

      match respC with
      | Choice1Of2 (HttpStatus 401 & HasAuth0WwwAuthenticate cp as resp) ->
#if LOGGING
        event Info "Received a 401 from {resourceUri} and found Auth0 client parameters; will attempt to retry with token"
        |> setField "clientParams" cp
        |> setField "resourceUri" req.url
        |> logger.logSimple
#endif
        (resp :> System.IDisposable).Dispose()
        let! retryC = tryGetResponseWithAuthSource u2cp2atOJ cp req
        return Alt.always retryC
      | _ ->
        return Alt.always respC
    }

  let tryGetResponseWithRetryOnAuthRequired (u2cp2atOJ : System.Uri -> ClientParams -> #Job<Auth0Token option>) req =
    tryGetResponse req
    |> tryWithRetryOnAuthRequired u2cp2atOJ req

type CacheExpirationParameters =
  { NowJob : Job<int64>
    DefaultMaxAge : int64
    TimeoutMaxAge : int64
    FailureMaxAge : int64
  }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module CacheExpirationParameters =
  let epoch = System.DateTimeOffset(1970, 1, 1, 0, 0, 0, System.TimeSpan.Zero).UtcTicks
  let create getNow defMaxAge toMaxAge failMaxAge =
    { NowJob = getNow
      DefaultMaxAge = defMaxAge
      TimeoutMaxAge = toMaxAge
      FailureMaxAge = failMaxAge
    }
  let create' defMaxAge toMaxAge failMaxAge =
    (create ^ Job.result ^ (System.DateTimeOffset.UtcNow.UtcTicks - epoch) / System.TimeSpan.TicksPerSecond) defMaxAge toMaxAge failMaxAge

  let mustNotExpireInNextSeconds cep s = fun v exp -> job {
    let! now = cep.NowJob
    return
      if exp > now + s then
        Some v
      else
        None
  }

type TokenCacheEntry =
  { Value : TokenCacheValue
    Expiration : int64
  }
and TokenCacheValue =
  | Responsive of Auth0Token
  | Unresponsive of Auth0ApiFailure

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module TokenCacheEntry =
#if LOGGING
  let logger = Log.createHiera [| "HttpFs"; "Auth0"; "TokenCache" |]
#endif

  let ofAuthResult defaultMaxAge timeoutMaxAge failureMaxAge ar =
    match ar with
    | Authentication.AuthOk t ->
      let exp =
        JwtToken.tryDecodePayload t.IdToken
        |> Choice.map JwtTokenPayload.expirationTime
        |> Choice.dimap (Option.orDefault defaultMaxAge) (always defaultMaxAge)
      { Value = Responsive t; Expiration = exp }
    | Authentication.AuthFail OperationTimedOut ->
      { Value = Unresponsive OperationTimedOut; Expiration = timeoutMaxAge }
    | Authentication.AuthFail f ->
      { Value = Unresponsive f; Expiration = failureMaxAge }

  let ofAuthResultJob cep ar = job {
    let! now = cep.NowJob
    return ofAuthResult (now + cep.DefaultMaxAge) (now + cep.TimeoutMaxAge) (now + cep.FailureMaxAge) ar
  }

  let valueToChoice = function
    | Responsive t -> Choice1Of2 t
    | Unresponsive f -> Choice2Of2 f

  let tryValidateExpiry mustBeGoodThrough ce =
    if ce.Expiration > mustBeGoodThrough then
      Some ce.Value
    else
      None

  let tryGetResponsiveValue validateExpiration cp tcePO : Promise<Auth0Token option> =
    memo ^ job {
      match tcePO with
      | None ->
#if LOGGING
        event Verbose "Cache miss for {clientParams}"
        |> setField "clientParams" cp
        |> logger.logSimple
#endif

        return None
      | Some tceP ->
#if LOGGING
        event Verbose "Cache hit for {clientParams}"
        |> setField "clientParams" cp
        |> logger.logSimple
#endif

        let! tce = Promise.read tceP
        let! tcvO = asJob ^ validateExpiration tce.Value tce.Expiration
        match tcvO with
        | Some tcv ->
          return valueToChoice tcv |> Option.ofChoice
        | None ->
#if LOGGING
          event Verbose "Cache expired for {clientParams}"
          |> setField "clientParams" cp
          |> logger.logSimple
#endif

          return None
    }

  let tryGetResponsiveValue' cep =
    tryGetResponsiveValue ^ CacheExpirationParameters.mustNotExpireInNextSeconds cep 10L

type TokenCache =
  TC of SharedMap<ClientParams,Promise<TokenCacheEntry>>

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module TokenCache =
#if LOGGING
  let logger = Log.createHiera [| "HttpFs"; "Auth0"; "TokenCache" |]
#endif

  let create () =
    SharedMap.create ()
    |> Job.map TC

  let putToken (TC sm) cp at exp =
    SharedMap.add cp (Promise { Value = Responsive at; Expiration = exp }) sm

  let putAuthenticationResult cep (TC sm) cp ar =
    SharedMap.add cp (memo ^ TokenCacheEntry.ofAuthResultJob cep ar) sm

  let tryGetEntry (TC sm) cp =
    Alt.prepare ^ job {
      let! m = SharedMap.freeze sm
      let tcePO = Map.tryFind cp m
      match tcePO with
      | None ->
        return Alt.always None
      | Some tceP ->
        let! tce = Promise.read tceP
        return Alt.always ^ Some ^ TokenCacheEntry.valueToChoice tce.Value
    }

  let tryGetToken cep (TC sm) cp =
    Alt.prepare ^ job {
      let! m = SharedMap.freeze sm
      let tcePO = Map.tryFind cp m
      return TokenCacheEntry.tryGetResponsiveValue' cep cp tcePO
    }

  let logAuthResultTime cp msg =
#if LOGGING
    msg
    |> setField "clientParams" cp
    |> logger.logSimple
#else
    ()
#endif

  let tryGetTokenWithFill cep (cp2arJ : ClientParams -> #Job<Authentication.AuthenticationResult>) ((TC sm) as tc) cp : Alt<Auth0Token option> =
    Alt.prepare ^ job {
      let! tO = tryGetToken cep tc cp
      match tO with
      | Some t ->
        return Alt.always ^ Some t
      | None ->
#if LOGGING
        event Debug "Cache has no reponsive entry for {clientParams}; Attempting to authenticate"
        |> setField "clientParams" cp
        |> logger.logSimple
#endif

        let tceP =
          cp2arJ cp
          |> Logging.timeJob ^ logAuthResultTime cp
          |> Job.bind ^ TokenCacheEntry.ofAuthResultJob cep
          |> memo
        do! Job.start ^ SharedMap.add cp tceP sm
        return asAlt ^ TokenCacheEntry.tryGetResponsiveValue' cep cp ^ Some tceP
    }

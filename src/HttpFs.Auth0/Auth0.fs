namespace HttpFs.Auth0

open Chiron
open Hopac
open Hopac.Infixes
open Hopac.Plus.Collections
open Hopac.Plus.Extensions
open HttpFs.Client
open HttpFs.Logging
open HttpFs.Logging.Message

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

  let stopwatchToMessage (swTicks : Hopac.Plus.Extensions.StopwatchTicks) =
    gauge (StopwatchTicks.toMicroseconds swTicks) "µs"

  let timeJob (doLog : Message -> unit) (xJ : Job<'x>) =
    Job.timeFun (stopwatchToMessage >> doLog) xJ

  let timeAlt (doLog : Message -> unit) (doLogNack: Message -> unit) (xA : Alt<'a>) : Alt<'a> =
    Alt.timeFun (stopwatchToMessage >> doLog) (stopwatchToMessage >> doLogNack) xA

module Authentication =
  let logger = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication" |]

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
    event Verbose "Reading authentication response"
    |> logger.logSimple

    let! bStrC = Response.readBodyAsString resp |> Job.catch
    match bStrC with
    | Choice1Of2 bStr ->
      event Verbose "Read authentication response"
      |> setField "length" ^ String.length bStr
      |> logger.logSimple

      let (arC : Choice<AuthenticationResult,string>) =
        Json.tryParse bStr
        |> Choice.bind Json.tryDeserialize
      match arC with
      | Choice1Of2 ar ->
        match ar with
        | AuthOk _ ->
          logger.log Verbose ^ eventX "Successfully decoded authentication response"
        | AuthFail f ->
          event Warn "Authentication API reported an error during authentication"
          |> setField "error" f
          |> logger.logSimple

        return ar
      | Choice2Of2 err ->
        event Warn "Error while trying to deserialize authentication response"
        |> setField "error" err
        |> logger.logSimple

        return AuthFail ^ DeserializationError err
    | Choice2Of2 ex ->
      event Warn "Error while trying to read authentication response"
      |> addExn ex
      |> logger.logSimple

      return AuthFail ^ Auth0ApiFailure.ApiException ex
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

  let deDot = String.replace "." "_"

  let logResponse (r : Response) : unit =
    let logLevel =
      match r.statusCode with
      | x when x >= 200 && x < 300 -> Debug
      | x when x >= 400 && x < 500 -> Warn
      | _ -> Info

    logger.log logLevel ^ fun ll ->
      event ll "Received response from authentication API {url} with status code {statusCode}"
      |> setField "statusCode" r.statusCode
      |> setField "url" ^ string r.responseUri

  let logResponseTime (uri : System.Uri) msg =
    let logger = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "tryAuthenticate"; "responseTime" |]
    let loggerHost = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "tryAuthenticate"; "responseTime"; deDot uri.Host |]
    let loggerPath = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "tryAuthenticate"; "responseTime"; deDot uri.Host; deDot uri.AbsolutePath |]
    msg |> logger.logSimple
    msg |> loggerHost.logSimple
    msg |> loggerPath.logSimple

  let logNack (uri : System.Uri) msg =
    let logger = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "tryAuthenticate"; "cancelled" |]
    let loggerHost = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "tryAuthenticate"; "cancelled"; deDot uri.Host |]
    let loggerPath = Log.createHiera [| "HttpFs"; "Auth0"; "Authentication"; "tryAuthenticate"; "cancelled"; deDot uri.Host; deDot uri.AbsolutePath |]
    msg |> logger.logSimple
    msg |> loggerHost.logSimple
    msg |> loggerPath.logSimple

  let tryAuthenticate (req : Request) : Alt<AuthenticationResult> =
    Alt.withNackJob ^ fun nack ->
      let outCh = Ch ()
      let doAlt = job {
#if LOG
        event Debug "Attempting to authenticate with {url}"
        |> setField "url" ^ string req.url
        |> logger.logSimple
#endif

        let respA =
          tryGetResponse req
          |> Logging.timeAlt (logResponseTime req.url) (logNack req.url)

        let! rC =
              nack ^=>. Alt.never
          <|> respA

        match rC with
        | Choice1Of2 r ->
          use r = r
          logResponse r
          let! ar = extractAuthResult r
          return! outCh *<- ar
        | Choice2Of2 ex ->
            match ex with
            | :? System.Net.WebException as exn when exn.Status = System.Net.WebExceptionStatus.Timeout ->
              event Info "Authentication request timed out after {timeout} milliseconds"
              |> setField "timeout" req.timeout
              |> logger.logSimple

              return! outCh *<- AuthFail OperationTimedOut
            | ex ->
              event Info "Authentication request failed with an exception"
              |> addExn ex
              |> logger.logSimple

              return! outCh *<- (AuthFail ^ Auth0ApiFailure.ApiException ex)
      }
      Job.queue doAlt >>-. outCh

  let credSourceLog = Log.createHiera [|"HttpFs"; "Auth0"; "Authentication"; "retrieveCredentials" |]

  let tryAuthenticateFromSource (u2cp2acOJ : System.Uri -> ClientParams -> #Job<Auth0Credentials option>) (uri : System.Uri) (cp : ClientParams) : Alt<_> =
    Alt.withNackJob ^ fun nack ->
      let outCh = Ch ()
      let doAlt : Job<unit> = job {
        logger.log Verbose
          ( eventX "Attempting to retrieve credentials for {resourceUri} with {authenticationHost}:{clientId}"
            >> setField "resourceUri" ^ string uri
            >> setField "authenticationHost" cp.AuthenticationHost
            >> setField "clientId" ^ string cp.ClientId
          )

        let! acO =
          asJob ^ u2cp2acOJ uri cp
          |> Logging.timeJob
            (    setField "resourceUri" ^ string uri
              >> setField "authenticationHost" cp.AuthenticationHost
              >> setField "clientId" ^ string cp.ClientId
              >> credSourceLog.logSimple
            )

        match acO with
        | Some ac ->
          logger.log Debug
            ( eventX "Found credentials for {resourceUri} with {authenticationHost}:{clientId}"
              >> setField "resourceUri" ^ string uri
              >> setField "authenticationHost" cp.AuthenticationHost
              >> setField "clientId" ^ string cp.ClientId
            )

          return!
                nack ^=>. Alt.never
            <|> tryAuthenticate (createRequest cp ac) ^=> Ch.give outCh
        | None ->
          event Info "Unable to find credentials for {resourceUri} with {authenticationHost}:{clientId}"
          |> setField "resourceUri" ^ string uri
          |> setField "authenticationHost" cp.AuthenticationHost
          |> setField "clientId" ^ string cp.ClientId
          |> logger.logSimple

          return! outCh *<- AuthFail NoCredentials
      }
      Job.queue doAlt >>-. outCh


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
  let logger = Log.createHiera [| "HttpFs"; "Auth0"; "Auth0Client" |]
  let tokenSourceLog = Log.createHiera [| "HttpFs"; "Auth0"; "Auth0Client"; "retrieveToken" |]

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
      logger.log Verbose
        ( eventX "Attempting to retrieve authentication token for {resourceUri} with {authenticationHost}:{clientId}"
          >> setField "resourceUri" ^ string uri
          >> setField "authenticationHost" cp.AuthenticationHost
          >> setField "clientId" ^ string cp.ClientId
        )

      let! atO =
        asJob ^ u2cp2atOJ uri cp
        |> Logging.timeJob
          (    setField "resourceUri" ^ string uri
            >> setField "authenticationHost" cp.AuthenticationHost
            >> setField "clientId" ^ string cp.ClientId
            >> tokenSourceLog.logSimple
          )

      match atO with
      | Some _ ->
        logger.log Verbose
          ( eventX "Found authentication token for {resourceUri} with {authenticationHost}:{clientId}"
            >> setField "resourceUri" ^ string uri
            >> setField "authenticationHost" cp.AuthenticationHost
            >> setField "clientId" ^ string cp.ClientId
          )

      | None ->
        logger.log Warn
          ( eventX "Unable to find credentials for {resourceUri} with {authenticationHost}:{clientId}"
            >> setField "resourceUri" ^ string uri
            >> setField "authenticationHost" cp.AuthenticationHost
            >> setField "clientId" ^ string cp.ClientId
          )

      return atO
  }

  let addAuth0TokenHeaderFromSource (u2cp2atOJ: System.Uri -> ClientParams -> #Job<Auth0Token option>) cp req = job {
      let! atO = tryGetAuth0TokenWithLogging u2cp2atOJ req.url cp
      match atO with
      | Some at ->
        let setHeader = Request.setHeader ^ Authorization ^ Auth0Token.toHttpAuthorizationHeaderString at
        return setHeader req
      | None ->
        return req
    }

  let tryGetResponseWithAuthSource (u2cp2atOJ : System.Uri -> ClientParams -> #Job<Auth0Token option>) cp req =
    Alt.withNackJob ^ fun nack ->
      let outCh = Ch ()
      let doAlt : Job<unit> = job {
        let! atO = tryGetAuth0TokenWithLogging u2cp2atOJ req.url cp
        let req1 = Option.fold (flip addAuth0TokenHeader) req atO

        return!
              nack ^=>. Alt.never
          <|> tryGetResponse req1 ^=> Ch.give outCh
      }
      Job.queue doAlt >>-. outCh

  let tryWithRetryOnAuthRequired (u2cp2atOJ : System.Uri -> ClientParams -> #Job<Auth0Token option>) req (respCJ : #Job<_>) =
    Alt.withNackJob ^ fun nack ->
      let outCh = Ch ()
      let doAlt : Job<unit> = job {
        event Verbose "Requesting resource {resourceUri}"
        |> setField "resourceUri" ^ string req.url
        |> logger.logSimple

        let! respC = asJob ^ respCJ

        match respC with
        | Choice1Of2 (HttpStatus 401 & HasAuth0WwwAuthenticate cp as resp) ->
          event Info "Received a 401 from {resourceUri} and found Auth0 client parameters; will attempt to retry with token"
          |> setField "authenticationHost" cp.AuthenticationHost
          |> setField "clientId" ^ string cp.ClientId
          |> setField "resourceUri" ^ string req.url
          |> logger.logSimple

          (resp :> System.IDisposable).Dispose()
          do! nack ^=>. Alt.never
          <|> tryGetResponseWithAuthSource u2cp2atOJ cp req ^=> Ch.give outCh
        | _ ->
          return! outCh *<- respC
      }
      Job.queue doAlt >>-. outCh

  let tryGetResponseWithRetryOnAuthRequired (u2cp2atOJ : System.Uri -> ClientParams -> #Job<Auth0Token option>) req =
    tryGetResponse req
    |> tryWithRetryOnAuthRequired u2cp2atOJ req

type CacheExpirationParameters =
  { NowJob : Job<SecondsSinceEpoch>
    DefaultMaxAge : SecondsSinceEpoch
    TimeoutMaxAge : SecondsSinceEpoch
    FailureMaxAge : SecondsSinceEpoch
  }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module CacheExpirationParameters =
  let create getNow defMaxAge toMaxAge failMaxAge =
    { NowJob = getNow
      DefaultMaxAge = defMaxAge
      TimeoutMaxAge = toMaxAge
      FailureMaxAge = failMaxAge
    }
  let create' defMaxAge toMaxAge failMaxAge =
    create Clock.getSecondsSinceEpoch defMaxAge toMaxAge failMaxAge

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
  | Responsive of t:Auth0Token
  | Unresponsive of f:Auth0ApiFailure

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module TokenCacheEntry =
  let loggerReq = Log.createHiera [| "HttpFs"; "Auth0"; "TokenCache"; "cacheRequest" |]
  let loggerHit = Log.createHiera [| "HttpFs"; "Auth0"; "TokenCache"; "cacheHit" |]
  let loggerMiss = Log.createHiera [| "HttpFs"; "Auth0"; "TokenCache"; "cacheMiss" |]
  let loggerExpired = Log.createHiera [| "HttpFs"; "Auth0"; "TokenCache"; "cacheExpired" |]

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

  let ofAuthResultJob cep arJ = job {
    let! ar = asJob arJ
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
    let doLog (logger : Logger) msg =
      logger.log Verbose
        ( eventX msg
          >> setField "authenticationHost" cp.AuthenticationHost
          >> setField "clientId" ^ string cp.ClientId
        )
    memo ^ job {
      doLog loggerReq "Cache request for {authenticationHost}:{clientId}"
      match tcePO with
      | None ->
        doLog loggerMiss "Cache miss for {authenticationHost}:{clientId}"

        return None
      | Some tceP ->
        doLog loggerHit "Cache hit for {authenticationHost}:{clientId}"

        let! tce = Promise.read tceP
        let! tcvO = asJob ^ validateExpiration tce.Value tce.Expiration
        match tcvO with
        | Some tcv ->
          return valueToChoice tcv |> Option.ofChoice
        | None ->
          doLog loggerExpired "Cache expired for {authenticationHost}:{clientId}"

          return None
    }

  let tryGetResponsiveValue' cep =
    tryGetResponsiveValue ^ CacheExpirationParameters.mustNotExpireInNextSeconds cep 10L

type TokenCache =
  TC of SharedMap<ClientParams,Promise<TokenCacheEntry>>

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module TokenCache =
  let logger = Log.createHiera [| "HttpFs"; "Auth0"; "TokenCache" |]

  let create () =
    SharedMap.create ()
    |> Job.map TC

  let putToken (TC sm) cp at exp =
    SharedMap.add cp (Promise { Value = Responsive at; Expiration = exp }) sm

  let putAuthenticationResultJob cep (TC sm) cp arJ =
    Alt.prepare
      ( Promise.queue (TokenCacheEntry.ofAuthResultJob cep arJ)
        >>- fun tceP -> SharedMap.add cp tceP sm
      )

  let tryGetEntry (TC sm) cp = job {
      let! m = SharedMap.freeze sm
      let tcePO = Map.tryFind cp m
      match tcePO with
      | None ->
        return None
      | Some tceP ->
        let! tce = Promise.read tceP
        return Some tce
    }

  let tryGetToken cep (TC sm) cp = job {
      let! m = SharedMap.freeze sm
      let tcePO = Map.tryFind cp m
      return! TokenCacheEntry.tryGetResponsiveValue' cep cp tcePO
    }

  let logAuthResultTime cp =
       setField "authenticationHost" cp.AuthenticationHost
    >> setField "clientId" ^ string cp.ClientId
    >> logger.logSimple

  let tryGetTokenWithFill cep (cp2arJ : ClientParams -> #Job<Authentication.AuthenticationResult>) ((TC sm) as tc) cp : Job<Auth0Token option> = job {
      let! tO = tryGetToken cep tc cp
      match tO with
      | Some t ->
        return Some t
      | None ->
        event Debug "Cache has no reponsive entry for {authenticationHost}:{clientId}; Attempting to authenticate"
        |> setField "authenticationHost" cp.AuthenticationHost
        |> setField "clientId" ^ string cp.ClientId
        |> logger.logSimple

        let tceP =
          cp2arJ cp
          |> Logging.timeJob ^ logAuthResultTime cp
          |> TokenCacheEntry.ofAuthResultJob cep
          |> memo
        do! Job.start ^ SharedMap.add cp tceP sm
        return! TokenCacheEntry.tryGetResponsiveValue' cep cp ^ Some tceP
    }

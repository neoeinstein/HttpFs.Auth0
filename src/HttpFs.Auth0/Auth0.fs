namespace HttpFs.Auth0

open Chiron
open Hopac
open Hopac.Plus.Collections
open HttpFs.Client

module MimeTypes =
  let [<Literal>] JsonString = "application/json"
  let Json = ContentType.parse JsonString |> Option.get

module Json =
  let inline writeMixin (a : ^a) =
    (^a : (static member ToJson: ^a -> Json<unit>) a)

  let inline readMixin json =
    (^a : (static member FromJson: ^a -> Json<'a>) Unchecked.defaultof<_>) json

type ClientId = ClientId of string

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module ClientId =
  let inline toString (ClientId i) = i

type RefreshToken = RefreshToken of string

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module RefreshToken =
  let inline toString (RefreshToken i) = i

type JwtToken = JwtToken of string

type JwtTokenPayload =
  { Issuer : string
    Subject : string
    Audience : string
    Expiry : int64
    IssuedAt : int64
  }
  static member FromJson (_ : JwtTokenPayload) =
    let (<!>) = Chiron.Operators.(<!>)
    let (<*>) = Chiron.Operators.(<*>)
    let mk i s a e v =
      { Issuer = i; Subject = s; Audience = a
        Expiry = e; IssuedAt = v
      }
    mk
    <!> Json.read "iss"
    <*> Json.read "sub"
    <*> Json.read "aud"
    <*> Json.read "exp"
    <*> Json.read "iat"

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module JwtToken =
  let inline toString (JwtToken i) = i

  let tryDecodePayload (JwtToken token) =
    let parts = token |> String.split '.'
    match parts with
    | [ payload ] | [ _; payload; _ ] ->
      let paddedPayload =
        match String.length payload % 4 with
        | 0 -> Choice1Of2 payload
        | 1 -> Choice2Of2 "Absurd: payload length % 4 was 1"
        | 2 -> Choice1Of2 <| payload + "=="
        | 3 -> Choice1Of2 <| payload + "="
        | _ -> Choice2Of2 "Absurd: payload length % 4 was not 0, 2, or 3"
      flip Choice.bind paddedPayload <| fun p ->
        try
          System.Convert.FromBase64String p
          |> System.Text.Encoding.UTF8.GetString
          |> Json.tryParse
          |> Choice.bind (Json.tryDeserialize : _ -> Choice<JwtTokenPayload,_>)
        with ex -> Choice2Of2 (string ex)
    | _ -> Choice2Of2 "Invalid token"

  let [<Literal>] GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type AccessToken = AccessToken of string

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module AccessToken =
  let inline toString (AccessToken i) = i

type TokenType = TokenType of string

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module TokenType =
  let inline toString (TokenType t) = t

  let bearer = TokenType "bearer"
  let basic = TokenType "basic"
  let digest = TokenType "digest"

  let create str =
    match str with
    | "bearer" -> bearer
    | "basic" -> basic
    | "digest" -> digest
    | _ -> TokenType str

type HttpAuthorizationToken =
  { TokenType : TokenType
    IdToken : JwtToken
  }
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module HttpAuthorizationToken =
  let toAuthorizationHeaderValue t =
    sprintf "%s %s" (TokenType.toString t.TokenType) (JwtToken.toString t.IdToken)

type Auth0Client =
  { AuthenticationHost : string
    ClientId : ClientId
  }

type AuthenticationScope =
  | OpenIdOnly
  | Offline of deviceName:string
  static member ToJson (x:AuthenticationScope) =
    let ( *>) = Chiron.Operators.( *>)
    match x with
    | OpenIdOnly ->
      Json.write "scope" "openid"
    | Offline d ->
      Json.write "scope" "openid offline_access"
      *> Json.write "device" d

type AuthenticationCredentials =
  | UsernamePassword of connection:string * username:string * password:string
  | IdTokenCred of JwtToken
  static member ToJson (x: AuthenticationCredentials) =
    let ( *>) = Chiron.Operators.( *>)
    match x with
    | UsernamePassword (c,u,p) ->
      Json.write "connection" c
      *> Json.write "username" u
      *> Json.write "password" p
      *> Json.write "grant_type" "password"
    | IdTokenCred (JwtToken t) ->
      Json.write "id_token" t
      *> Json.write "grant_type" JwtToken.GrantType

type AuthenticationRequest =
  { ClientId : ClientId
    Credentials : AuthenticationCredentials
    Scope : AuthenticationScope
  }
  static member ToJson (x : AuthenticationRequest) =
    let ( *>) = Chiron.Operators.( *>)
    Json.write "client_id" (ClientId.toString x.ClientId)
    *> Json.writeMixin x.Credentials
    *> Json.writeMixin x.Scope

type Auth0Error =
  { ErrorType : string
    Description : string
  }
  static member FromJson (_ : Auth0Error) =
    let (<!>) = Chiron.Operators.(<!>)
    let (<*>) = Chiron.Operators.(<*>)
    let mk e d =
      { ErrorType = e
        Description = d
      }
    mk
    <!> Json.read "error"
    <*> Json.read "error_description"

type ApiFailure =
  | ApiError of Auth0Error
  | DeserializationError of string
  | Exception of exn
  | OperationTimedOut

type AuthenticationResponse =
  { IdToken : JwtToken
    AccessToken : AccessToken
    RefreshToken : RefreshToken option
    TokenType : TokenType
  }
  static member FromJson (_ : AuthenticationResponse) =
    let (<!>) = Chiron.Operators.(<!>)
    let (<*>) = Chiron.Operators.(<*>)
    let mk i a r t =
      { IdToken = JwtToken i
        AccessToken = AccessToken a
        RefreshToken = Option.map RefreshToken r
        TokenType = TokenType.create t
      }
    mk
    <!> Json.read "id_token"
    <*> Json.read "access_token"
    <*> Json.readOrDefault "refresh_token" None
    <*> Json.read "token_type"

type AuthenticationResult =
  | AuthenticationSuccess of AuthenticationResponse
  | AuthenticationFailed of ApiFailure
  static member FromJson (_ : AuthenticationResult) =
    let (<!>) = Chiron.Operators.(<!>)
    let mk (idToken : string option) =
      match idToken with
      | Some _ ->
        AuthenticationSuccess <!> Json.readMixin
      | None ->
        (AuthenticationFailed << ApiError) <!> Json.readMixin
    Json.bind (Json.read "id_token") mk

type DelegationCredentials =
  | IdTokenCred of JwtToken
  | RefreshTokenCred of RefreshToken
  static member ToJson (x : DelegationCredentials) =
    let ( *>) = Chiron.Operators.( *>)
    match x with
    | IdTokenCred t ->
      Json.write "id_token" (JwtToken.toString t)
      *> Json.write "grant_type" JwtToken.GrantType
    | RefreshTokenCred t ->
      Json.write "refresh_token" (RefreshToken.toString t)
      *> Json.write "grant_type" "refresh_token"

type DelegationRequest =
  { ClientId : ClientId
    Credentials : DelegationCredentials
    Target : ClientId option
    Scope : AuthenticationScope
  }
  static member ToJson (x : DelegationRequest) =
    let ( *>) = Chiron.Operators.( *>)
    Json.write "client_id" (ClientId.toString x.ClientId)
    *> Json.writeMixin x.Credentials
    *> Json.writeUnlessDefault "target" None (Option.map ClientId.toString x.Target)
    *> Json.writeMixin x.Scope

type HttpRequestResult =
  | AuthenticationRequired of Auth0Client * Response
  | UnhandledResponse of Response

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
    let ks = cks |> Array.map (fun c -> c.Value)
    let vs = cvs |> Array.map (fun c -> c.Value)
    let kvps = Array.zip ks vs
    Map.ofArray kvps

  let extractValues str =
    HeaderValueRegex.Matches str
    |> (fun mc ->
      let cms : Match array = Array.zeroCreate mc.Count
      mc.CopyTo (cms, 0)
      cms)
    |> Array.map (fun m -> String.toLowerInvariant m.Groups.["token"].Value, zipKvps m)

  let tryFindChallengeType (TokenType ct) =
       Array.tryFind (fst >> String.equalsConstantTime ct)
    >> Option.map snd

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Auth0Client =
  let (|HttpStatus|_|) status (resp : Response) =
    if resp.statusCode = status then
      Some ()
    else
      None

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
          |> Option.bind (Map.tryFind "client_id")
          |> Option.map ClientId
        )

  let (|HasAuth0WwwAuthenticate|_|) (resp : Response) =
    Map.tryFind WWWAuthenticate resp.headers
    |> Option.bind (WwwAuthenticate.extractValues >> WwwAuthenticate.tryFindChallengeType TokenType.bearer)
    |> Option.bind extractAuth0Params

  let buildAuthorizeRequest a0client (a0creds : AuthenticationCredentials) a0scope =
    let url = System.Uri(sprintf "https://%s/oauth/ro" a0client.AuthenticationHost, System.UriKind.Absolute)
    let a0reqBody : AuthenticationRequest =
      { ClientId = a0client.ClientId
        Credentials = a0creds
        Scope = a0scope
      }
    let a0req =
      Request.create Post url
      |> Request.setHeader (ContentType MimeTypes.Json)
      |> Request.setHeader (UserAgent "HttpFs.Auth0")
      |> Request.setHeader (Accept MimeTypes.JsonString)
      |> Request.autoDecompression (DecompressionScheme.GZip ||| DecompressionScheme.Deflate)
      |> Request.keepAlive true
      |> Request.timeout 10000<ms>
      |> Request.bodyString (a0reqBody |> Json.serialize |> Json.format)
    a0req

  let knockOnFrontDoor (req : Request) = job {
    printfn "Making request..."
    let! resp = getResponse req
    printfn "Received response..."
    return
      match resp with
      | HttpStatus 401 & HasAuth0WwwAuthenticate a0client ->
        printfn "got 401"
        AuthenticationRequired (a0client, resp)
      | _ ->
        printfn "got non-challenge response"
        UnhandledResponse resp
  }

  let addAuthHeaders =
    HttpAuthorizationToken.toAuthorizationHeaderValue
    >> Authorization
    >> Request.setHeader

  let getResponseWithAuth0Credentials a0creds =
    addAuthHeaders a0creds
    >> getResponse

  let getResponseWithAuth0OnChallenge (tryGetCredentials : Auth0Client -> Job<HttpAuthorizationToken option>) (req : Request) = job {
    let! result = knockOnFrontDoor req
    match result with
    | AuthenticationRequired (a0client, resp) ->
      let! creds = tryGetCredentials a0client
      printfn "Credential lookup: %A" creds
      match creds with
      | Some c ->
        return! getResponseWithAuth0Credentials c req
      | None ->
        return resp
    | UnhandledResponse resp ->
      return resp
  }

  let getAuthorizationResponse : _ -> Job<AuthenticationResult> =
    getResponse
    >> Job.bind Response.readBodyAsString
    >> Job.map (Json.tryParse >> Choice.bind Json.tryDeserialize)
    >> Job.catch
    >> Job.map
      ( function
        | Choice1Of2 (Choice1Of2 authresult) -> authresult
        | Choice1Of2 (Choice2Of2 parseError) -> AuthenticationFailed (DeserializationError parseError)
        | Choice2Of2 (:? System.Net.WebException as exn) when exn.Status = System.Net.WebExceptionStatus.Timeout -> AuthenticationFailed OperationTimedOut
        | Choice2Of2 exn -> AuthenticationFailed (Exception exn)
      )


type CredentialCacheEntry =
  { IdToken : JwtToken
    AccessToken : AccessToken
    RefreshToken : RefreshToken option
    TokenType : TokenType
    Expiration : int64
  }

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module CredentialCacheEntry =
  let createFromAuthenticationResponse (a0authResp : AuthenticationResponse) expiry =
    { IdToken = a0authResp.IdToken
      AccessToken = a0authResp.AccessToken
      RefreshToken = a0authResp.RefreshToken
      TokenType = a0authResp.TokenType
      Expiration = expiry
    }

  let tryCreateFromAuthenticationResponse (a0authResp : AuthenticationResponse) =
    JwtToken.tryDecodePayload a0authResp.IdToken
    |> Choice.map (fun p -> p.Expiry |> createFromAuthenticationResponse a0authResp)

  let tryValidateExpiry mustBeGoodThrough ce =
    if ce.Expiration > mustBeGoodThrough then
      Some ce
    else
      None

  let toHttpAuthorizationToken (x : CredentialCacheEntry) : HttpAuthorizationToken =
    { TokenType = x.TokenType
      IdToken = x.IdToken
    }

type CredentialCache =
  CredentialCache of SharedMap<Auth0Client,CredentialCacheEntry>

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module CredentialCache =
  let create () =
    SharedMap.create ()
    |> Job.map CredentialCache

  let cacheResponseIfValid (CredentialCache cs) a0client a0authResp = Alt.prepareFun <| fun () ->
    let ceResult = CredentialCacheEntry.tryCreateFromAuthenticationResponse a0authResp
    match ceResult with
    | Choice1Of2 ce ->
      SharedMap.add a0client ce cs
    | Choice2Of2 _ ->
      Alt.unit ()

  let cacheResponseWithExpiry (CredentialCache cs) a0client a0authResp expiry =
    let ce = CredentialCacheEntry.createFromAuthenticationResponse a0authResp expiry
    SharedMap.add a0client ce cs

  let tryRetrieveToken (CredentialCache cs) a0client =
    SharedMap.freeze cs
    |> Job.map (Map.tryFind a0client)

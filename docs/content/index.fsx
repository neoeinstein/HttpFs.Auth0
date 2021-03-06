(*** hide ***)
// This block of code is omitted in the generated HTML documentation. Use
// it to define helpers that you do not want to show in the documentation.
#I "../../bin/HttpFs.Auth0"
#r "Hopac.Core.dll"
#r "Hopac.dll"
#r "HttpFs.dll"
#r "HttpFs.Auth0.dll"
open System

Hopac.Hopac.run <| Hopac.Job.unit ()

module Choice =
  let getOrFail xyC =
    match xyC with
    | Choice1Of2 x -> x
    | Choice2Of2 y -> failwithf "Choice.getOrFail"

module Uri =
  let isAbsolute (uri : Uri) = uri.IsAbsoluteUri
  let toString (uri : Uri) = uri.ToString()

(*** define: logging ***)
open HttpFs.Logging

Global.initialise
  { Global.DefaultConfig with
      getLogger = fun _ -> ConsoleWindowTarget(Verbose) :> Logger
  }
(**
HttpFs.Auth0
============

**HttpFs.Auth0** provides constructs which make it easier to use Auth0 when interacting with protected APIs.

This library focuses on server-to-server interactions, where one service needs to authenticate itself to
another service in order to gain access to a provided resource. This library also includes a
[`TokenCache`](reference/httpfs-auth0-tokencachemodule.html) for transiently caching ID tokens while they
remain valid.

**HttpFs.Auth0** also supports a knock-first workflow, where an attempt is made to interact with a resource first.
In this case, if the resource sends back a `401 Unauthorized` response, then the request can be retried after
(possibly generating and) adding the Auth0 token to the request.

<div class="row">
  <div class="span1"></div>
  <div class="span6">
    <div class="well well-small" id="nuget">
      The HttpFs.Auth0 library can be <a href="https://nuget.org/packages/HttpFs.Auth0">installed from NuGet</a>:
      <pre>PM> Install-Package HttpFs.Auth0</pre>
    </div>
  </div>
  <div class="span1"></div>
</div>

Example
-------

The following shows a simple flow for authenticating with an API. It uses the Auth0 demo app credentials from
their [SSO Heroku application](https://github.com/auth0-samples/auth0-sso-dashboard). You can get your own Auth0
account to test with by going to [https://www.auth0.com](https://auth0.com/how-it-works).

*)
(*** define-output: main ***)
open Hopac
open HttpFs.Client
open HttpFs.Auth0

let cp =
  { AuthenticationHost = "fabrikam.auth0.com"
    ClientId = ClientId.create "ZDC7qh6mcXaQT6ilyiTWPmmfFI7L0aTs" }

let ac =
  UsernamePassword ("FabrikamAD","publicdemo","TestUser123")

let atJ =
  Authentication.createRequest cp ac
  |> Authentication.tryAuthenticate
  |> Alt.afterFun Authentication.AuthenticationResult.toChoice

let at = run atJ |> Choice.getOrFail

let respJ =
  Request.createUrl Get "http://www.example.com/protectedResource"
  |> Auth0Client.addAuth0TokenHeader at
  |> getResponse
(**

The next example demonstrates how to set up a token cache and validate the
client parameters returned by the protected resource against a whitelist of
known client parameters. This helps to ensure that a malicious resource can't
trick you into sending your credentials to a malicious authentication server.

The token cache helps to reduce the load on the Authentication API, keeping
the token in memory while the token remains valid.

*)

let cep = CacheExpirationParameters.create' 300L 10L 60L
let tc = run <| TokenCache.create ()

let credentialMap = Map.ofList [ cp, ac ]
let prefixWhitelist = [ Uri "https://www.example.com/", cp ]

let tryGetCredentialsJob (uri : Uri) cp =
  let isWhitelisted (uri : Uri) (whitelistedUri : Uri, validParams : ClientParams) =
    if whitelistedUri.IsBaseOf uri && cp = validParams then Some cp else None
  prefixWhitelist
  |> List.tryPick (isWhitelisted uri)
  |> Option.bind (fun cp -> Map.tryFind cp credentialMap)
  |> Job.result

let tryAuthenticateClient uri cp =
  Authentication.tryAuthenticateFromSource tryGetCredentialsJob uri cp

let tryGetAuthToken uri =
  TokenCache.tryGetTokenWithFill cep (tryAuthenticateClient uri) tc

let respCToStringJ = function
  | Choice1Of2 resp -> Response.readBodyAsString resp
  | Choice2Of2 ex -> Job.result <| "Failed: " + string ex

let respStrA =
  Request.createUrl Get "http://www.example.com/protectedResource"
  |> Auth0Client.tryGetResponseWithRetryOnAuthRequired tryGetAuthToken
  |> Alt.afterJob respCToStringJ

(**

Logging
-------

This library uses the logging façade provided by `Http.Fs` under then
`HttpFs.Logging` namespace. You can enable logging by initializing the
façade and hooking it to your logging framework of choice.

Setting up logging:

*)
(*** include: logging ***)
(**

Example logs:

*)
(*** include-output: main ***)
(**

Note that you may see the following warning from Hopac. We are working to make
this warning go away in a future version, but you should experience no adverse
effects as the `run` utilized by Logary returns very quickly.

    WARNING: You are making a blocking call from within a Hopac worker thread, which means that your program may deadlock.
    First occurrence (there may be others):
      at System.Environment.GetStackTrace(Exception e, Boolean needFileInfo)
      at System.Environment.get_StackTrace()
      at Hopac.Core.Condition.Wait(Object o, Int32& v)
      at Hopac.Scheduler.run[x](Scheduler sr, Job`1 xJ)
      at Logary.Adapters.Facade.LogaryFacadeAdapter.values@188.Invoke(Object x)
      at <StartupCode$FSharp-Core>.$Reflect.Invoke@961-4.Invoke(T1 inp)
      at HttpFs.Logging.Global.f@1-1(Flyweight this, Unit _arg1)
      at HttpFs.Logging.Global.Flyweight.withLogger[a](FSharpFunc`2 action)
      at HttpFs.Auth0.Auth0Client.u2xJ@1-3[a](FSharpFunc`2 u2cp2atOJ, Uri uri, ClientParams cp, Unit unitVar)
      at HttpFs.Auth0.Auth0Client.tryGetAuth0TokenWithLogging@526-39.Do()
      at Hopac.Core.JobDelay`1.DoJob(Worker& wr, Cont`1 xK)
      at Hopac.Core.Always`1.DoJob(Worker& wr, Cont`1 xK)
      at Hopac.Promise`1.Fulfill.Do(Worker& wr, T t)
      at Hopac.Promise`1.Fulfill.DoWork(Worker& wr)
      at Hopac.Core.Worker.Run(Scheduler sr, Int32 me)
      at System.Threading.ExecutionContext.RunInternal(ExecutionContext executionContext, ContextCallback callback, Object state, Boolean preserveSyncCtx)
      at System.Threading.ExecutionContext.Run(ExecutionContext executionContext, ContextCallback callback, Object state, Boolean preserveSyncCtx)
      at System.Threading.ExecutionContext.Run(ExecutionContext executionContext, ContextCallback callback, Object state)
      at System.Threading.ThreadHelper.ThreadStart()

Samples & documentation
-----------------------

The API reference is automatically generated from Markdown comments in the library implementation.

 * [API Reference](reference/index.html) contains automatically generated documentation for all types, modules
   and functions in the library. This includes additional brief samples on using most of the
   functions.

Contributing and copyright
--------------------------

The project is hosted on [GitHub][gh] where you can [report issues][issues], fork
the project and submit pull requests. If you're adding a new public API, please also
consider adding [samples][content] that can be turned into a documentation. You might
also want to read the [library design notes][readme] to understand how it works.

The library is available under Apache 2.0 license, which allows modification and
redistribution for both commercial and non-commercial purposes. For more information see the
[License file][license] in the GitHub repository.

  [content]: https://github.com/fsprojects/HttpFs.Auth0/tree/master/docs/content
  [gh]: https://github.com/fsprojects/HttpFs.Auth0
  [issues]: https://github.com/fsprojects/HttpFs.Auth0/issues
  [readme]: https://github.com/fsprojects/HttpFs.Auth0/blob/master/README.md
  [license]: https://github.com/fsprojects/HttpFs.Auth0/blob/master/LICENSE.txt
*)

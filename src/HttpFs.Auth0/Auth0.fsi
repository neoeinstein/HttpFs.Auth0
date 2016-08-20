namespace HttpFs.Auth0

module Client =
  val getResponseWithAuth0OnChallenge : HttpFs.Client.Request -> Hopac.Job<Response>

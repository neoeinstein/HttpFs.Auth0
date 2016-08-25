module HttpFs.Auth0.Tests

open HttpFs.Auth0
open NUnit.Framework

[<Test>]
let ``initial tautology`` () =
  let result = 42
  printfn "%i" result
  Assert.AreEqual(42,result)

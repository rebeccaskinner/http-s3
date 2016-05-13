{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.S3.SignatureSpec (main, spec) where

import Test.Hspec
import Test.QuickCheck

import Network.HTTP.S3.Signature
import qualified Network.HTTP as HTTP
import Network.URI
import Data.Maybe
import Control.Monad

main :: IO ()
main = hspec spec

instance (Show a) => Eq (HTTP.Request a) where
  a == b = (show a) == (show b)

fakeEndpoint :: String
fakeEndpoint = "http://fakes3-endpoint.test"

fakeEndpointURI :: URI
fakeEndpointURI = fromJust $ parseURI "http://fakes3-endpoint.test/admin"

fakeBadGetRequest :: HTTP.Request String
fakeBadGetRequest = HTTP.Request fakeEndpointURI HTTP.GET [] ""

fakeGetRequest :: HTTP.Request String
fakeGetRequest = HTTP.getRequest fakeEndpoint

fakeAccess :: String
fakeAccess = "fakeaccess1"

fakeSecret :: String
fakeSecret = "fakesecret1"

spec :: Spec
spec = do
  describe "signRequest" $ do
    context "When missing headers" $ do
      it "Returns 'Nothing' when missing a date header" $ do
        (signRequest fakeAccess fakeSecret fakeBadGetRequest) `shouldBe` Nothing

    context "When given valid input data" $ do
      it "Returns 'Just (Request Text)'" $ do
        pendingWith "Requires fuller implementation"


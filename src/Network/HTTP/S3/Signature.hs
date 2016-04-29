{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.S3.Signature where
import qualified Network.HTTP as HTTP

import Data.Text

signRequest :: String -> String -> HTTP.Request a -> Maybe (HTTP.Request a)
signRequest access secret request = Nothing

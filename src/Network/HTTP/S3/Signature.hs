{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.S3.Signature where
import qualified Network.HTTP as HTTP
import Data.Time.Clock
import Data.Time.Format
import qualified Data.ByteString.Char8 as B
import Crypto.Hash
import Crypto.MAC.HMAC
import Data.List

data SigningRecord = SigningRecord { sigMethod :: HTTP.RequestMethod
                                   , sigContent :: B.ByteString
                                   , sigContentType :: B.ByteString
                                   , sigDate :: UTCTime
                                   , sigResource :: Request B.ByteString
                                   }

data Request a = HostStyleRequest a | PathStyleRequest a

md5sum :: B.ByteString -> B.ByteString
md5sum = B.pack . show . (hash :: B.ByteString -> Digest MD5)

md5Str :: String -> B.ByteString
md5Str = md5sum . B.pack

rfc1123DateString :: String
rfc1123DateString = "%a, %d %b %Y %H:%M:%S %Z"

httpDateFormat :: FormatTime t => t -> B.ByteString
httpDateFormat = B.pack . formatTime defaultTimeLocale rfc1123DateString

{- For host style requests this assumes that everything before the first '.'
   is the bucket name, and everything after it until the first '/' or end of
   the string is the hostname -}
canonizeRequestString :: Request B.ByteString -> B.ByteString
canonizeRequestString req =
    let (PathStyleRequest req') = toPathStyle req in req'
    where
      toPathStyle pth@(PathStyleRequest _) = pth
      toPathStyle (HostStyleRequest hostStyle) =
          let (bucket, host') = B.break (=='.') hostStyle
              host = if B.null host' then B.empty else B.tail host'
          in PathStyleRequest hostStyle


hashSigningRequest :: SigningRecord -> B.ByteString
hashSigningRequest sigRecord =
    B.intercalate (B.pack "\n") [ (B.pack . show) (sigMethod sigRecord)
                                  , md5sum (sigContent sigRecord)
                                  , sigContentType sigRecord
                                  , (httpDateFormat . sigDate) sigRecord
                                  , (canonizeRequestString . sigResource) sigRecord
                                  ]

mkSigningRequest req = SigningRecord { sigMethod = rqMethod req
                                     , sigContent = (md5Sum . rqBody) req
                                     ,

signRequest :: B.ByteString -> B.ByteString -> HTTP.Request B.ByteString -> Maybe (HTTP.Request B.ByteString)
signRequest access secret request =
    let requestSig = hashSigningRequest $ mkSigningRequest request
        signedReq = hmac secret requestSig :: Digest SHA1
    in Nothing --(pack "AWS)

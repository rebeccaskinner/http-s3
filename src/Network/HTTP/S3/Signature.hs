{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.S3.Signature where
import Network.HTTP
import Data.Time.Clock
import Data.Time.Format
import qualified Data.ByteString.Char8 as B
import Crypto.Hash
import Crypto.MAC.HMAC
import Data.List
import Data.Maybe

data SigningRecord = SigningRecord { sigMethod :: RequestMethod
                                   , sigContent :: B.ByteString
                                   , sigContentType :: B.ByteString
                                   , sigDate :: B.ByteString
                                   , sigResource :: B.ByteString
                                   }

data S3RequestType = HostStyleRequest | PathStyleRequest deriving (Eq, Show)

data S3Request a = S3Request { s3Access      :: B.ByteString
                             , s3Secret      :: B.ByteString
                             , s3RequestType :: S3RequestType
                             , s3Request     :: Request a
                             }

md5sum :: B.ByteString -> B.ByteString
md5sum = B.pack . show . (hash :: B.ByteString -> Digest MD5)

md5Str :: String -> B.ByteString
md5Str = md5sum . B.pack

rfc1123DateString :: String
rfc1123DateString = "%a, %d %b %Y %H:%M:%S %Z"

httpDateFormat :: FormatTime t => t -> B.ByteString
httpDateFormat = B.pack . formatTime defaultTimeLocale rfc1123DateString

canonizeRequestURI :: S3Request a -> Maybe (S3Request a)
canonizeRequestURI req@(S3Request _ _ PathStyleRequest _) = req
canonizeRequestURI req =
    let reqURI = rqURI req
    in do
      (reqPath, reqHost) <- breakURI reqURI
      
    canonizeRequestURI $
                       req { s3RequestType = PathStyleRequest
                           , s3Request = pathRequest
                           }
    where
      uriHostPortion u = (uriRegName <$>) $ parseURI u >>= uriAuthority
      breakURI u = (\(a,b) -> ((,) a) <$> b) (uriPath u, uriHostPortion u)
      hostToPathRequest :: Request a -> Request a
      hostToPathRequest request =

hashSigningRequest :: SigningRecord -> B.ByteString
hashSigningRequest sigRecord =
    B.intercalate (B.pack "\n") [ (B.pack . show) (sigMethod sigRecord)
                                  , md5sum (sigContent sigRecord)
                                  , sigContentType sigRecord
                                  , (httpDateFormat . sigDate) sigRecord
                                  , (canonizeRequestString . sigResource) sigRecord
                                  ]

mkSigningRequest req =
    let dateStr = getRequestHeader HdrDate req
        contentTypeStr = getRequestHeader HdrContentType req
        canonicalResource = (canonizeRequestString . B.pack . rqURI) req
    in SigningRecord { sigMethod = rqMethod req
                     , sigContent = (md5sum . rqBody) req
                     , sigContentType = contentTypeStr
                     , sigDate = dateStr
                     , sigResource = canonicalResource
                     }
    where
      getRequestHeader header request =
          (B.pack . fromJust) (findHeader header request)

signRequest :: B.ByteString -> B.ByteString -> Request B.ByteString -> Maybe (Request B.ByteString)
signRequest access secret request =
    let requestSig = hashSigningRequest $ mkSigningRequest request
        signedReq = hmac secret requestSig :: Digest SHA1
    in Nothing --(pack "AWS)

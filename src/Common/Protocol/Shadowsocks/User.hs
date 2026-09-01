{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Common.Protocol.Shadowsocks.User (ServerUser (..), ServerUserManager (ServerUserManager), getUserByHash, newServerUser, userCount) where

import qualified BLAKE3
import Common.Crypto (Key)
import Common.Util (showBase64, showByteString)
import Control.Concurrent.STM (STM)
import qualified Data.ByteArray.Sized as Sized
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.Text (Text)
import qualified Data.Text as T
import qualified StmContainers.Map as STMMap

data ServerUser = ServerUser Text Key StrictByteString deriving (Eq)

instance Show ServerUser where
  show (ServerUser name key identityHash) = "N:" ++ T.unpack name ++ ", K:" ++ showBase64 key ++ ", IH:" ++ showByteString identityHash

newServerUser :: Text -> StrictByteString -> ServerUser
newServerUser name key =
  let digest = BLAKE3.hash Nothing [key] :: BLAKE3.Digest BLAKE3.DEFAULT_DIGEST_LEN
      identityHash = B.take 16 $ Sized.unSizedByteArray (Sized.convert digest :: Sized.SizedByteArray BLAKE3.DEFAULT_DIGEST_LEN StrictByteString)
   in ServerUser name key identityHash

data ServerUserManager = ServerUserManager (STMMap.Map StrictByteString ServerUser)

instance Show ServerUserManager where
  show _ = "ServerUserManager"

getUserByHash :: ServerUserManager -> StrictByteString -> STM (Maybe ServerUser)
getUserByHash manager identityHash = STMMap.lookup identityHash $ managerMap manager

userCount :: ServerUserManager -> STM Int
userCount manager = STMMap.size $ managerMap manager

managerMap :: ServerUserManager -> STMMap.Map StrictByteString ServerUser
managerMap (ServerUserManager value) = value

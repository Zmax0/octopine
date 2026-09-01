{-# LANGUAGE TemplateHaskell #-}

module Common.Codec.Shadowsocks.Identity (Identity (Identity), salt, requestSalt, user, newIdentity) where

import Common.Crypto.Aead (CipherKind (keySize))
import Common.Dice (rollBytes)
import Common.Protocol.Shadowsocks (Salt (Salt))
import Common.Protocol.Shadowsocks.User (ServerUser)
import Control.Lens (makeLenses)

data Identity = Identity {_salt :: Salt, _requestSalt :: Maybe Salt, _user :: Maybe ServerUser}

makeLenses ''Identity

newIdentity :: CipherKind -> IO Identity
newIdentity kind = do
  salt' <- Salt <$> (rollBytes $ keySize kind)
  return $ Identity salt' Nothing Nothing

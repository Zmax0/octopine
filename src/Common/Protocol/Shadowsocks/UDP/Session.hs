{-# LANGUAGE TemplateHaskell #-}

module Common.Protocol.Shadowsocks.UDP.Session (Session (Session), clientSessionId, new, packetId, serverSessionId, user) where

import Common.Dice (Dice (roll))
import Common.Protocol.Shadowsocks (Mode (..), PacketId)
import Common.Protocol.Shadowsocks.User (ServerUser (ServerUser))
import Control.Lens (makeLenses)
import qualified Data.Text as T
import Data.Word (Word64)

data Session = Session {_clientSessionId :: Word64, _serverSessionId :: Word64, _packetId :: PacketId, _user :: Maybe ServerUser}

instance Show Session where
  show (Session c s p Nothing) = "{C:" ++ show c ++ ", S:" ++ show s ++ ", P:" ++ show p ++ "}"
  show (Session c s p (Just (ServerUser n _ _))) = "{C:" ++ show c ++ ", S:" ++ show s ++ ", P:" ++ show p ++ ", U:" ++ T.unpack n ++ "}"

new :: Mode -> IO Session
new Server = (\random -> Session 0 random 0 Nothing) <$> roll
new Client = (\random -> Session random 0 0 Nothing) <$> roll

makeLenses ''Session

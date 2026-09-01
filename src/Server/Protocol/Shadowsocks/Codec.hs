{-# LANGUAGE TemplateHaskell #-}

module Server.Protocol.Shadowsocks.Codec (DecodedDatagram (DecodedDatagram), PacketCodec (PacketCodec), PayloadCodec, SaltCache, ShadowsocksSettings (ShadowsocksSettings), checkSaltReplay, decodeDatagram, encodeDatagram, newPayloadCodec) where

import Common.Codec (LeftoverByteString)
import qualified Common.Codec.Shadowsocks.Aead as Aead
import qualified Common.Codec.Shadowsocks.Aead2022 as Aead2022
import Common.Codec.Shadowsocks.Aead2022.TCP (SaltCache, checkSaltReplay)
import qualified Common.Codec.Shadowsocks.Aead2022.TCP as Aead2022.TCP
import qualified Common.Codec.Shadowsocks.Identity as Identity
import qualified Common.Codec.Shadowsocks.TCP.Session as TCPSession
import qualified Common.Codec.Socks.Address as SocksAddress
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind, keySize, tagSize)
import Common.Crypto.Aead.Authenticator (Authenticator, open, seal)
import Common.Crypto.Aead.NonceGenerator (IncreasingNonceGenerator)
import Common.Dice (rollBytes)
import Common.Exception (AppExceptionKind (InvariantError, ProtocolError), throwApp)
import Common.Logger (debug_, loggers)
import Common.Network.Address (Address (SockAddr), parseAddr)
import Common.Protocol.Shadowsocks (Mode (Server), Salt (Salt))
import Common.Protocol.Shadowsocks.Aead (hkdfsha1)
import Common.Protocol.Shadowsocks.Aead2022 (isAead2022)
import qualified Common.Protocol.Shadowsocks.UDP.Session as UdpSession
import Common.Protocol.Shadowsocks.User (ServerUser (ServerUser), ServerUserManager)
import Control.Exception (SomeException)
import Control.Lens ((&), (.~), (^.))
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State.Strict (StateT, get, put, runState, runStateT)
import Data.Binary.Get (runGetOrFail)
import Data.Binary.Put (runPut)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Server.Protocol (NewCodecResult, RelayFrame (OpenTcp, TcpData, UdpData), ServerCodec (decode, encode))
import qualified Server.Protocol.Shadowsocks.Aead2022.UDP as Aead2022.UDP

$(loggers "Server" ['debug_])

data ShadowsocksSettings = ShadowsocksSettings CipherKind Key Bool SaltCache ServerUserManager

data ChunkEncoder = EncodeChunk Aead.AeadEncoder | PendingHeader TCPSession.Session Aead.AeadEncoder | PendingSalt Salt ChunkEncoder deriving (Show)

type ChunkDecoder = Aead.AeadDecoder

data PayloadCodec = PayloadCodec TCPSession.Session ChunkEncoder ChunkDecoder deriving (Show)

newPayloadCodec :: ShadowsocksSettings -> StrictByteString -> IO (NewCodecResult PayloadCodec)
newPayloadCodec (ShadowsocksSettings kind key hasUsers saltCache userManager) msg = do
  if isAead2022 kind
    then do
      identity <- Identity.newIdentity kind
      let session = TCPSession.Session Server Nothing identity
      (decoded, session') <- runStateT (Aead2022.TCP.initDecoder kind key hasUsers saltCache userManager msg) session
      case decoded of
        Nothing -> return $ Right Nothing
        Just (leftover, plaintext, decoder) ->
          case session' ^. TCPSession.address of
            Nothing -> throwApp ProtocolError "AEAD2022 request header did not contain an address"
            Just address -> do
              peerAddr <- parseAddr address
              let salt = session' ^. TCPSession.identity . Identity.salt
                  encoder = PendingSalt salt $ newChunkEncoder kind key session'
                  frames = OpenTcp peerAddr : [TcpData plaintext | not $ B.null plaintext]
              return $ Right $ Just (leftover, frames, PayloadCodec session' encoder decoder)
    else do
      let (salt, ciphertext) = B.splitAt (keySize kind) msg
          decoder = newChunkDecoder kind key $ Salt salt
      (result, decoder') <- runStateT (Aead.decodeChunks ciphertext) decoder
      case result of
        Right (Just (leftover, plaintext)) ->
          case runGetOrFail SocksAddress.decode $ B.fromStrict plaintext of
            Right (pending, _, address) -> do
              peerAddr <- parseAddr address
              identity <- Identity.newIdentity kind
              let session = TCPSession.Session Server (Just address) identity
                  salt' = identity ^. Identity.salt
                  encoder = PendingSalt salt' $ newChunkEncoder kind key session
                  payload = B.toStrict pending
                  frames = OpenTcp peerAddr : [TcpData payload | not $ B.null payload]
              return $ Right $ Just (leftover, frames, PayloadCodec session encoder decoder')
            Left (_, _, err) -> throwApp ProtocolError err
        Right Nothing -> return $ Right Nothing
        Left exception -> return $ Left exception

instance ServerCodec PayloadCodec where
  encode OpenTcp {} = throwApp InvariantError "shadowsocks codec does not encode connection frames"
  encode (TcpData msg) = do
    PayloadCodec session encoder decoder <- get
    (encoded, encoder') <- lift $ runStateT (encodeChunk msg) encoder
    put $ PayloadCodec session encoder' decoder
    return encoded
  encode UdpData {} = throwApp InvariantError "shadowsocks stream codec does not encode UDP frames"

  decode msg = do
    PayloadCodec session encoder decoder <- get
    (result, decoder') <- lift $ runStateT (Aead.decodeChunks msg) decoder
    put $ PayloadCodec session encoder decoder'
    return $ fmap (fmap (\(leftover, payload) -> (leftover, TcpData payload))) result

encodeChunk :: StrictByteString -> StateT ChunkEncoder IO StrictByteString
encodeChunk chunk = do
  encoder <- get
  case encoder of
    EncodeChunk auth -> do
      (ciphertext, auth') <- lift $ runStateT (Aead.encodeChunk chunk) auth
      put $ EncodeChunk auth'
      return ciphertext
    PendingSalt (Salt salt) nextEncoder -> do
      put nextEncoder
      ciphertext <- encodeChunk chunk
      return $ salt <> ciphertext
    PendingHeader session (Aead.AeadEncoder auth) -> do
      ((header, leftover), auth') <- lift $ runStateT (payloadHeader session chunk) auth
      put $ EncodeChunk $ Aead.AeadEncoder auth'
      if B.null leftover then return header else (header <>) <$> encodeChunk leftover

payloadHeader :: TCPSession.Session -> StrictByteString -> StateT (Authenticator IncreasingNonceGenerator) IO (StrictByteString, StrictByteString)
payloadHeader (TCPSession.Session mode _ identity) msg = do
  (fixed, variable, leftover) <- Aead2022.TCP.newHeader mode (identity ^. Identity.requestSalt) msg
  return (fixed <> variable, leftover)

newChunkEncoder :: CipherKind -> Key -> TCPSession.Session -> ChunkEncoder
newChunkEncoder kind key session@(TCPSession.Session _ _ identity) =
  let salt = identity ^. Identity.salt
   in case (isAead2022 kind, identity ^. Identity.user) of
        (True, Just (ServerUser _ userKey _)) -> PendingHeader session $ Aead2022.newEncoder kind userKey salt
        (True, Nothing) -> PendingHeader session $ Aead2022.newEncoder kind key salt
        (False, _) -> EncodeChunk $ Aead.AeadEncoder $ Aead.newAuthenticator kind $ hkdfsha1 key salt

newChunkDecoder :: CipherKind -> Key -> Salt -> ChunkDecoder
newChunkDecoder kind key salt = Aead.DecodeLength $ Aead.newAuthenticator kind $ hkdfsha1 key salt

data PacketCodec = PacketCodec CipherKind Key ServerUserManager deriving (Show)

data DecodedDatagram = DecodedDatagram LeftoverByteString RelayFrame UdpSession.Session deriving (Show)

encodeDatagram :: PacketCodec -> UdpSession.Session -> RelayFrame -> IO (StrictByteString, UdpSession.Session)
encodeDatagram (PacketCodec kind key _) session (UdpData msg addr)
  | isAead2022 kind = do
      let currentPacketId = session ^. UdpSession.packetId
      if currentPacketId == maxBound
        then throwApp ProtocolError "server UDP packet ID exhausted"
        else return ()
      let session' = session & UdpSession.packetId .~ currentPacketId + 1
      _debug_ $ "send to client; session=" ++ show session'
      encoded <- Aead2022.UDP.encodeServerPacketAead2022 kind key session' (SockAddr addr) msg
      return (encoded, session')
  | otherwise = do
      _debug_ $ "send to client; session=" ++ show session
      salt <- rollBytes $ keySize kind
      let auth = Aead.newAuthenticator kind $ hkdfsha1 key $ Salt salt
          address = B.toStrict $ runPut $ SocksAddress.encode $ SockAddr addr
          (ciphertext, _) = runState (seal $ address <> msg) auth
      return (salt <> ciphertext, session)
encodeDatagram _ _ _ = throwApp InvariantError "only encodes UdpData frames"

decodeDatagram :: PacketCodec -> StrictByteString -> IO (Either SomeException (Maybe DecodedDatagram))
decodeDatagram (PacketCodec kind key userManager) msg = do
  if isAead2022 kind
    then do
      (payload, address, clientSession) <- Aead2022.UDP.decodeClientPacketAead2022 kind key userManager msg
      peerAddr <- parseAddr address
      return $ Right $ Just $ DecodedDatagram B.empty (UdpData payload peerAddr) clientSession
    else do
      let saltLength = keySize kind
          minLength = saltLength + tagSize kind
      if B.length msg < minLength
        then throwApp ProtocolError $ "packet too short, bytes=" ++ show (B.length msg)
        else do
          let (salt, ciphertext) = B.splitAt saltLength msg
              auth = Aead.newAuthenticator kind $ hkdfsha1 key $ Salt salt
              (plaintext, _) = runState (open ciphertext) auth
          case runGetOrFail SocksAddress.decode $ B.fromStrict plaintext of
            Left (_, _, err) -> throwApp ProtocolError err
            Right (payload, _, address) -> do
              peerAddr <- parseAddr address
              return $ Right $ Just $ DecodedDatagram B.empty (UdpData (B.toStrict payload) peerAddr) (UdpSession.Session 0 0 0 Nothing)

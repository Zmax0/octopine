{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

{-
    Packet:
    +---------------------------+---------------------------+
    | encrypted separate header |       encrypted body      |
    +---------------------------+---------------------------+
    |            16B            | variable length + 16B tag |
    +---------------------------+---------------------------+
-}
{-
    Separate header:
    +------------+-----------+
    | session ID | packet ID |
    +------------+-----------+
    |     8B     |   u64be   |
    +------------+-----------+

    Client-to-server message header:
    +------+------------------+----------------+----------+------+----------+-------+
    | type |     timestamp    | padding length |  padding | ATYP |  address |  port |
    +------+------------------+----------------+----------+------+----------+-------+
    |  1B  | u64be unix epoch |     u16be      | variable |  1B  | variable | u16be |
    +------+------------------+----------------+----------+------+----------+-------+

    Server-to-client message header:
    +------+------------------+-------------------+----------------+----------+------+----------+-------+
    | type |     timestamp    | client session ID | padding length |  padding | ATYP |  address |  port |
    +------+------------------+-------------------+----------------+----------+------+----------+-------+
    |  1B  | u64be unix epoch |         8B        |     u16be      | variable |  1B  | variable | u16be |
    +------+------------------+-------------------+----------------+----------+------+----------+-------+
-}

module Server.Protocol.Shadowsocks.Aead2022.UDP (decodeClientPacketAead2022, encodeServerPacketAead2022) where

import Common.Codec.Shadowsocks.Aead2022 (newTimestamp, nextPaddingLength)
import qualified Common.Codec.Shadowsocks.Aead2022 as Aead2022
import qualified Common.Codec.Socks.Address as Address
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (Aead2022Blake3Aes128Gcm, Aead2022Blake3Aes256Gcm, Aead2022Blake3ChaCha20Poly1305, Aead2022Blake3ChaCha8Poly1305, tagSize), decrypt, encrypt)
import Common.Crypto.Aes (aes128EcbNoPaddingDecrypt, aes128EcbNoPaddingEncrypt, aes256EcbNoPaddingDecrypt, aes256EcbNoPaddingEncrypt)
import Common.Dice (rollBytes)
import Common.Exception (AppExceptionKind (ProtocolError), throwApp)
import Common.Logger (loggers, trace_)
import Common.Network.Address (Address)
import Common.Protocol.Shadowsocks (Mode (Client, Server))
import Common.Protocol.Shadowsocks.Aead2022 (supportEih)
import Common.Protocol.Shadowsocks.Aead2022.UDP (getNonceLength, newCipher)
import Common.Protocol.Shadowsocks.UDP.Session (Session (Session), clientSessionId, packetId, serverSessionId)
import Common.Protocol.Shadowsocks.User (ServerUser (ServerUser), ServerUserManager, getUserByHash, userCount)
import Common.Util (decodeWord64BE, encodeWord16BE, showByteString)
import Control.Concurrent.STM (atomically)
import Control.Lens ((^.))
import Control.Monad (when)
import Data.Binary.Get (getInt64be, getWord16be, getWord8, runGetOrFail, skip)
import Data.Binary.Put (runPut)
import Data.Bits (xor)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.ByteString.Builder (byteString, int64BE, toLazyByteString, word64BE, word8)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Data.Word (Word8)
import Formatting (format, int, (%))

$(loggers "s.p.s.a.UDP" ['trace_])

encodeServerPacketAead2022 :: CipherKind -> Key -> Session -> Address -> StrictByteString -> IO StrictByteString
encodeServerPacketAead2022 kind contextKey session@(Session _ _ _ user) addr msg = do
  paddingLength <- nextPaddingLength msg
  let nonceLength = getNonceLength kind
  nonce <- rollBytes nonceLength
  padding <- rollBytes paddingLength
  now <- newTimestamp
  let header = B.toStrict $ toLazyByteString $ buildHeader nonce now padding
      addr' = B.toStrict $ runPut $ Address.encode addr
      msg' = (header <> addr' <> msg)
  case kind of
    Aead2022Blake3Aes128Gcm -> pure $ aesEncrypt msg'
    Aead2022Blake3Aes256Gcm -> pure $ aesEncrypt msg'
    Aead2022Blake3ChaCha8Poly1305 -> pure $ chachaEncrypt nonceLength msg'
    Aead2022Blake3ChaCha20Poly1305 -> pure $ chachaEncrypt nonceLength msg'
    k -> throwApp ProtocolError $ show k ++ "is not an AEAD 2022 cipher"
  where
    buildHeader nonce' now' padding' =
      byteString nonce'
        <> word64BE (session ^. serverSessionId)
        <> word64BE (session ^. packetId)
        <> word8 (fromIntegral $ fromEnum Server)
        <> int64BE now'
        <> word64BE (session ^. clientSessionId)
        <> byteString (encodeWord16BE $ B.length padding')
        <> byteString padding'
    aesEncrypt plaintext = do
      let (header, tail') = B.splitAt 16 plaintext
          nonce = B.take 12 $ B.drop 4 header
          key = case user of
            Just (ServerUser _ userKey _) -> userKey
            Nothing -> contextKey
          cipherHeader = case kind of
            Aead2022Blake3Aes128Gcm -> aes128EcbNoPaddingEncrypt key header
            Aead2022Blake3Aes256Gcm -> aes256EcbNoPaddingEncrypt key header
            other -> error $ show other ++ " is not an AEAD 2022 AES cipher"
          cipher = newCipher kind key (session ^. serverSessionId)
          cipherTail = encrypt cipher nonce B.empty tail'
      (cipherHeader <> cipherTail)
    chachaEncrypt nonceLength plaintext = do
      let (nonce, plaintext') = B.splitAt nonceLength plaintext
          cipher = newCipher kind contextKey (session ^. serverSessionId)
          ciphertext = encrypt cipher nonce B.empty plaintext'
      (nonce <> ciphertext)

decodeClientPacketAead2022 :: CipherKind -> Key -> ServerUserManager -> StrictByteString -> IO (StrictByteString, Address, Session)
decodeClientPacketAead2022 kind contextKey userManager msg = do
  requireEih <- if supportEih kind then (> 0) <$> atomically (userCount userManager) else pure $ False
  let nonceLength = getNonceLength kind
      tagSize' = tagSize kind
      eihSize = if requireEih then 16 else 0
      headerLength = nonceLength + tagSize' + 8 + 8 + eihSize + 1 + 8 + 2
  when (B.length msg < headerLength) $ throwApp ProtocolError $ TL.unpack $ do
    format ("packet too short, at least " % int % " bytes, but found " % int % " bytes") headerLength $ B.length msg
  (sessionId, packetId', user, packet) <-
    if nonceLength == 0
      then do
        let (encryptedSessionIdPacketId, encryptedPacket) = B.splitAt 16 msg
        sessionIdPacketId <- case kind of
          Aead2022Blake3Aes128Gcm -> pure $ aes128EcbNoPaddingDecrypt contextKey encryptedSessionIdPacketId
          Aead2022Blake3Aes256Gcm -> pure $ aes256EcbNoPaddingDecrypt contextKey encryptedSessionIdPacketId
          other -> throwApp ProtocolError $ show other ++ " is not an AEAD 2022 AES cipher"
        let nonce = B.drop 4 sessionIdPacketId
            (sessionIdBytes, packetIdBytes) = B.splitAt 8 sessionIdPacketId
            sessionId = decodeWord64BE sessionIdBytes
            packetId' = decodeWord64BE packetIdBytes
        user <-
          if requireEih
            then do
              let (encryptedEih, _) = B.splitAt 16 encryptedPacket
              decryptedEih <- case kind of
                Aead2022Blake3Aes128Gcm -> pure $ aes128EcbNoPaddingDecrypt contextKey encryptedEih
                Aead2022Blake3Aes256Gcm -> pure $ aes256EcbNoPaddingDecrypt contextKey encryptedEih
                other -> throwApp ProtocolError $ show other ++ " is not an AEAD 2022 AES cipher"
              let eih = B.pack $ B.zipWith xor decryptedEih sessionIdPacketId
              _trace_ $ "packet header, EIH:" ++ showByteString decryptedEih ++ ", session_id:" ++ show sessionId ++ ", packet_id:" ++ show packetId'
              user' <- atomically $ getUserByHash userManager eih
              case user' of
                Nothing -> throwApp ProtocolError "user not found"
                Just user''@(ServerUser name _ _) -> do
                  _trace_ $ "user [" ++ T.unpack name ++ "] chosen by EIH"
                  return $ Just user''
            else return Nothing
        let key = case user of
              Just (ServerUser _ userKey _) -> userKey
              Nothing -> contextKey
            packetCiphertext = if requireEih then B.drop 16 encryptedPacket else encryptedPacket
            packet = decrypt (newCipher kind key sessionId) nonce B.empty packetCiphertext
        return (sessionId, packetId', user, packet)
      else do
        let (nonce, ciphertext) = B.splitAt nonceLength msg
            sessionId = decodeWord64BE ciphertext
            plaintext = decrypt (newCipher kind contextKey sessionId) nonce B.empty ciphertext
            (sessionIdBytes, packetAndHeader) = B.splitAt 8 plaintext
            (packetIdBytes, packet) = B.splitAt 8 packetAndHeader
        return (decodeWord64BE sessionIdBytes, decodeWord64BE packetIdBytes, Nothing, packet)
  case runGetOrFail ((,,) <$> getWord8 <*> getInt64be <*> getWord16be) (B.fromStrict packet) of
    Left (_, _, err) -> throwApp ProtocolError err
    Right (remaining, _, (streamType, timestamp, paddingLength)) -> do
      let expectedStreamType = fromIntegral $ fromEnum Client :: Word8
      when (streamType /= expectedStreamType) $ throwApp ProtocolError $ TL.unpack $ format ("invalid socket type, expecting " % int % ", but found " % int) expectedStreamType streamType
      Aead2022.validateTimestamp timestamp
      case runGetOrFail (skip (fromIntegral paddingLength) >> Address.decode) remaining of
        Left (_, _, err) -> throwApp ProtocolError err
        Right (payload, _, address) -> return (B.toStrict payload, address, Session sessionId 0 packetId' user)

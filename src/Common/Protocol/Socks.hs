module Common.Protocol.Socks (AddressType (Ipv4, Ipv6, Domain), CommandType (Connect, UdpAssociate, Bind)) where

data AddressType = Ipv4 | Domain | Ipv6 deriving (Show, Eq, Ord, Bounded)

instance Enum AddressType where
  fromEnum Ipv4 = 1
  fromEnum Domain = 3
  fromEnum Ipv6 = 4

  toEnum 1 = Ipv4
  toEnum 3 = Domain
  toEnum 4 = Ipv6
  toEnum _ = error "illegal byte value"

data CommandType = Connect | Bind | UdpAssociate deriving (Show, Eq, Ord, Bounded)

instance Enum CommandType where
  fromEnum Connect = 1
  fromEnum Bind = 2
  fromEnum UdpAssociate = 3

  toEnum 1 = Connect
  toEnum 2 = Bind
  toEnum 3 = UdpAssociate
  toEnum _ = error "illegal byte value"

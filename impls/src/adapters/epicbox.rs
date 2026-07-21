// Copyright 2019 The Epic Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::config::{EpicboxConfig, TorConfig};
use crate::epicbox::protocol::{
	ProtocolError, ProtocolRequest, ProtocolRequestV2, ProtocolResponseV2,
};
use crate::keychain::Keychain;
use crate::libwallet::crypto::{sign_challenge, Hex};
use crate::libwallet::message::EncryptedMessage;
use crate::util::secp::key::PublicKey;

use crate::libwallet::wallet_lock;
use crate::libwallet::{
	address, Address, EpicboxAddress, TxProof, DEFAULT_EPICBOX_PORT_443, DEFAULT_EPICBOX_PORT_80,
};
use crate::libwallet::{NodeClient, WalletInst, WalletLCProvider};

use crate::Error;

use crate::libwallet::{Slate, SlateVersion, VersionedSlate};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

use std::collections::HashMap;
use std::fmt;

use std::sync::Arc;
use std::thread::JoinHandle;

use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner;

use epic_wallet_util::epic_core::core::amount_to_hr_string;
use rand::rng;
use rand::seq::SliceRandom;
use std::env;
use std::net::TcpStream;
use std::string::ToString;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::spawn;

use tungstenite::connect;
use tungstenite::{protocol::WebSocket, stream::MaybeTlsStream};
use tungstenite::{Error as ErrorTungstenite, Message};

// Used to correlate relay acknowledgements with wallet transactions.
use uuid::Uuid;

// Copyright 2019 The vault713 Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


const CONNECTION_ERR_MSG: &str = "\nCan't connect to the epicbox server!\n\
	Check your epic-wallet.toml settings and make sure epicbox domain is correct.\n";

const EPICBOX_PROTOCOL_VERSION: &str = "3.0.0";

const SUBSCRIBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const RELAY_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Epicbox 'plugin' implementation
pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

#[derive(Debug, Clone)]
pub enum BrokerEvent {
	Subscribed,
	PostAck {
		slate_id: Uuid,
		epicboxtxid: String,
	},
	Made,
	Cancelled {
		epicboxtxid: String,
	},
}

/// Metadata for one PostSlate that is waiting for its relay acknowledgement.
///
/// `epicboxtxid` is absent for the initial state, because the destination
/// relay creates the stable transaction identifier. Every later state carries
/// the already-established identifier forward.
#[derive(Debug, Clone)]
struct PendingPost {
	slate_id: Uuid,
	epicboxtxid: Option<String>,
}

#[derive(Clone)]
pub struct EpicboxSubscriber {
	address: EpicboxAddress,
	broker: EpicboxBroker,
	secret_key: SecretKey,
	wallet_mode: String,
	is_node_synced: Arc<AtomicBool>,
}
#[derive(Clone)]
pub struct EpicboxPublisher {
	address: EpicboxAddress,
	broker: EpicboxBroker,
	secret_key: SecretKey,
	wallet_mode: String,
}

pub struct EpicboxListener {
	pub address: EpicboxAddress,
	pub publisher: EpicboxPublisher,
	pub subscriber: EpicboxSubscriber,
	pub handle: JoinHandle<()>,
}

#[derive(Clone)]
pub struct EpicboxChannel {
	dest: String,
	epicbox_config: Option<EpicboxConfig>,
}

#[derive(Clone)]
pub struct EpicboxListenChannel {
	_priv: (),
}

impl EpicboxListenChannel {
	pub fn new() -> Result<EpicboxListenChannel, Error> {
		Ok(EpicboxListenChannel { _priv: () })
	}
	pub fn listen<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		epicbox_config: EpicboxConfig,
		reconnections: &mut u32,
		is_node_synced: Arc<AtomicBool>,
		tor_config: TorConfig,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let (address, sec_key) = {
			let a_keychain = keychain_mask.clone();
			let a_wallet = wallet.clone();
			let mask = a_keychain.lock();
			let mut w_lock = a_wallet.lock();
			let lc = w_lock.lc_provider()?;
			let w_inst = lc.wallet_inst()?;
			let k = w_inst.keychain((&mask).as_ref())?;
			let parent_key_id = w_inst.parent_key_id();
			let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)?;
			let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key)?;

			let address = EpicboxAddress::new(
				pub_key.clone(),
				epicbox_config.epicbox_domain.clone(),
				epicbox_config.epicbox_port,
			);

			(address, sec_key)
		};
		let url = {
			let cloned_address = address.clone();
			match epicbox_config.epicbox_protocol_unsecure.unwrap_or(false) {
				true => format!(
					"ws://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_80)
				),
				false => format!(
					"wss://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_443)
				),
			}
		};
		let (tx, _rx): (Sender<BrokerEvent>, Receiver<BrokerEvent>) = channel();

		debug!("Connecting to the epicbox server at {} ..", url.clone());
		let (socket, _response) = connect(url.clone()).map_err(|e| {
			warn!("{}", Error::EpicboxTungstenite(format!("{}", e).into()));
			*reconnections += 1;
			Error::EpicboxTungstenite(format!("{}", e).into())
		})?;

		let publisher =
			EpicboxPublisher::new(address.clone(), sec_key, socket, tx, "listener".to_string())?;

		let mut subscriber = EpicboxSubscriber::new(&publisher, is_node_synced)?;

		let container = Container::new(epicbox_config.clone());
		let cpublisher = publisher.clone();
		let mask = keychain_mask.lock();
		let km = mask.clone();
		let controller = EpicboxController::new(
			container,
			cpublisher,
			wallet,
			km,
			reconnections,
			tor_config.clone(),
		)
		.expect("Could not init epicbox listener!");

		info!("Starting epicbox listener for: {}", address);
		subscriber.start(controller)
	}
}

/// Remove and stop the one-shot epicbox listener session, if present.
/// Closes the websocket and joins the subscriber thread.
fn stop_epicbox_listener(container: &Arc<Mutex<Container>>) {
	if let Some(l) = container
		.lock()
		.listeners
		.remove(&ListenerInterface::Epicbox)
	{
		let _ = l.stop();
	}
}

fn wait_for<F: FnMut(&BrokerEvent) -> bool>(
	rx: &Receiver<BrokerEvent>,
	deadline: std::time::Instant,
	mut want: F,
) -> bool {
	loop {
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		if remaining.is_zero() {
			return false;
		}
		match rx.recv_timeout(remaining) {
			Ok(ev) if want(&ev) => return true,
			Ok(_) => continue,
			Err(_) => return false, // timeout or subscriber thread gone
		}
	}
}

impl EpicboxChannel {
	/// new epicbox.
	pub fn new(
		dest: &String,
		epicbox_config: Option<EpicboxConfig>,
	) -> Result<EpicboxChannel, Error> {
		Ok(EpicboxChannel {
			dest: dest.clone(),
			epicbox_config: epicbox_config.clone(),
		})
	}

	pub fn send<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Option<SecretKey>,
		slate: &Slate,
		is_node_synced: Arc<AtomicBool>,
		tor_config: TorConfig,
	) -> Result<Slate, Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let config = match self.epicbox_config.clone() {
			None => EpicboxConfig::default(),
			Some(epicbox_config) => epicbox_config,
		};

		let container = Container::new(config.clone());

		// Keep the one-shot session alive until the relay acknowledges the
		// PostSlate and the stable epicboxtxid has been persisted locally.
		let (tx, rx): (Sender<BrokerEvent>, Receiver<BrokerEvent>) = channel();
		let listener = start_epicbox(
			container.clone(),
			wallet,
			keychain_mask,
			config,
			tx,
			is_node_synced,
			tor_config.clone(),
		)?;

		container
			.lock()
			.listeners
			.insert(ListenerInterface::Epicbox, listener);

		let vslate = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);

		if let Err(e) = container
			.lock()
			.listener(ListenerInterface::Epicbox)?
			.publish(&vslate, &self.dest, None)
		{
			stop_epicbox_listener(&container);
			return Err(e);
		}

		let ack_deadline = std::time::Instant::now() + RELAY_ACK_TIMEOUT;
		if !wait_for(&rx, ack_deadline, |event| {
			matches!(event, BrokerEvent::PostAck { .. })
		}) {
			warn!(
				"No relay acknowledgement for posted Slate within {:?}; \
				 the stable epicboxtxid was not confirmed as stored",
				RELAY_ACK_TIMEOUT
			);
		}

		stop_epicbox_listener(&container);

		let slate: Slate =
			VersionedSlate::into_version(slate.clone(), SlateVersion::V2).into();
		Ok(slate)
	}

	/// One-shot relay cancellation. Connect, establish the Epicbox session,
	/// send CancelTx for the stable transaction identifier, and wait until the
	/// relay returns TransactionCancelled. Local cancellation is performed by
	/// the subscriber before the confirmation event is emitted.
	pub fn cancel<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Option<SecretKey>,
		epicboxtxid: &String,
		is_node_synced: Arc<AtomicBool>,
		tor_config: TorConfig,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let config = match self.epicbox_config.clone() {
			None => EpicboxConfig::default(),
			Some(epicbox_config) => epicbox_config,
		};

		let container = Container::new(config.clone());
		let (tx, rx): (Sender<BrokerEvent>, Receiver<BrokerEvent>) = channel();

		let listener = start_epicbox(
			container.clone(),
			wallet,
			keychain_mask,
			config,
			tx,
			is_node_synced,
			tor_config.clone(),
		)?;

		container
			.lock()
			.listeners
			.insert(ListenerInterface::Epicbox, listener);

		let sub_deadline = std::time::Instant::now() + SUBSCRIBE_TIMEOUT;
		if !wait_for(&rx, sub_deadline, |event| {
			matches!(event, BrokerEvent::Subscribed)
		}) {
			stop_epicbox_listener(&container);
			return Err(Error::EpicboxTungstenite(
				format!(
					"Could not send CancelTx: Epicbox session ended or the \
					 subscription did not establish within {:?}",
					SUBSCRIBE_TIMEOUT
				)
				.into(),
			));
		}

		if let Err(e) = container
			.lock()
			.listener(ListenerInterface::Epicbox)?
			.cancel(epicboxtxid)
		{
			stop_epicbox_listener(&container);
			return Err(e);
		}

		let confirm_deadline = std::time::Instant::now() + RELAY_ACK_TIMEOUT;
		let confirmed = wait_for(&rx, confirm_deadline, |event| {
			matches!(
				event,
				BrokerEvent::Cancelled { epicboxtxid: id } if id == epicboxtxid
			)
		});

		stop_epicbox_listener(&container);

		if confirmed {
			Ok(())
		} else {
			Err(Error::EpicboxTungstenite(
				format!(
					"No TransactionCancelled response from relay for [{}]; \
					 local transaction was not confirmed cancelled",
					epicboxtxid
				)
				.into(),
			))
		}
	}
}

pub fn start_epicbox<L, C, K>(
	container: Arc<Mutex<Container>>,
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Option<SecretKey>,
	config: EpicboxConfig,
	tx: Sender<BrokerEvent>,
	is_node_synced: Arc<AtomicBool>,
	tor_config: TorConfig,
) -> Result<Box<dyn Listener>, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let (address, sec_key) = {
		let a_wallet = wallet.clone();
		let mut w_lock = a_wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w_inst = lc.wallet_inst()?;
		let k = w_inst.keychain(keychain_mask.as_ref())?;
		let parent_key_id = w_inst.parent_key_id();
		let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)?;
		let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key)?;

		let address = EpicboxAddress::new(
			pub_key.clone(),
			config.epicbox_domain.clone(),
			config.epicbox_port,
		);
		(address, sec_key)
	};
	let url = {
		let cloned_address = address.clone();
		match config.epicbox_protocol_unsecure.unwrap_or(false) {
			true => format!(
				"ws://{}:{}",
				cloned_address.domain,
				cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_80)
			),
			false => format!(
				"wss://{}:{}",
				cloned_address.domain,
				cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_443)
			),
		}
	};
	debug!("Connecting to the epicbox server at {} ..", url.clone());
	let (mut socket, _) = connect(url.clone()).expect(CONNECTION_ERR_MSG);

	match socket.get_mut() {
		MaybeTlsStream::Plain(stream) => {
			stream
				.set_read_timeout(Some(std::time::Duration::from_secs(1)))
				.expect("Could not configure epicbox read timeout");
		}
		MaybeTlsStream::NativeTls(stream) => {
			stream
				.get_ref()
				.set_read_timeout(Some(std::time::Duration::from_secs(1)))
				.expect("Could not configure epicbox read timeout");
		}
		_ => {
			warn!("Unable to configure epicbox read timeout for this TLS backend");
		}
	}
	let publisher =
		EpicboxPublisher::new(address.clone(), sec_key, socket, tx, "send".to_string())?;
	let subscriber = EpicboxSubscriber::new(&publisher, is_node_synced)?;

	let mut csubscriber = subscriber.clone();
	let cpublisher = publisher.clone();
	let mut reconnections = 0;

	let handle = spawn(move || {
		let controller = EpicboxController::new(
			container,
			cpublisher,
			wallet,
			keychain_mask,
			&mut reconnections,
			tor_config.clone(),
		)
		.expect("Could not init epicbox controller!");

		if let Err(e) = csubscriber.start(controller) {
			warn!("Epicbox subscriber ended abnormally: {}", e);
		}
	});

	Ok(Box::new(EpicboxListener {
		address,
		publisher,
		subscriber,
		handle,
	}))
}

impl Listener for EpicboxListener {
	fn interface(&self) -> ListenerInterface {
		ListenerInterface::Epicbox
	}

	fn address(&self) -> String {
		self.address.stripped()
	}

	fn publish(
		&self,
		slate: &VersionedSlate,
		to: &String,
		epicboxtxid: Option<&String>,
	) -> Result<(), Error> {
		let address = EpicboxAddress::from_str(to)?;

		// The subscriber must remain open to receive and persist the relay
		// acknowledgement. Teardown is performed by the caller.
		self.publisher
			.post_slate(slate, &address, false, epicboxtxid)
	}

	fn cancel(&self, epicboxtxid: &String) -> Result<(), Error> {
		self.publisher.cancel_tx(epicboxtxid)
	}

	fn stop(self: Box<Self>) -> Result<(), Error> {
		let listener = *self;
		listener.subscriber.stop();
		let _ = listener.handle.join();
		Ok(())
	}
}

impl EpicboxPublisher {
	pub fn new(
		address: EpicboxAddress,
		secret_key: SecretKey,
		socket: WebSocket<MaybeTlsStream<TcpStream>>,
		tx: Sender<BrokerEvent>,
		wallet_mode: String,
	) -> Result<Self, Error> {
		Ok(Self {
			address,
			broker: EpicboxBroker::new(socket, tx)?,
			secret_key,
			wallet_mode,
		})
	}
}

impl Publisher for EpicboxPublisher {
	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		close_connection: bool,
		epicboxtxid: Option<&String>,
	) -> Result<(), Error> {
		self.broker.post_slate(
			slate,
			to,
			&self.address,
			&self.secret_key,
			epicboxtxid,
		)?;

		if close_connection {
			self.broker.stop();
		}

		Ok(())
	}

	fn cancel_tx(&self, epicboxtxid: &String) -> Result<(), Error> {
		self.broker
			.post_cancel_tx(epicboxtxid, &self.address, &self.secret_key)
	}
}

impl EpicboxSubscriber {
	pub fn new(
		publisher: &EpicboxPublisher,
		is_node_synced: Arc<AtomicBool>,
	) -> Result<Self, Error> {
		Ok(Self {
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
			wallet_mode: publisher.wallet_mode.clone(),
			is_node_synced, // Can be updated by the caller.
		})
	}
}

pub struct EpicboxController<'a, P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	publisher: P,
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	/// Keychain mask
	pub keychain_mask: Option<SecretKey>,
	pub reconnections: &'a mut u32,
	pub tor_config: TorConfig,
}
pub struct Container {
	pub config: EpicboxConfig,
	pub account: String,
	pub listeners: HashMap<ListenerInterface, Box<dyn Listener>>,
}
impl Container {
	pub fn new(config: EpicboxConfig) -> Arc<Mutex<Self>> {
		let container = Self {
			config,
			account: String::from("default"),
			//TODO: reduce listeners
			listeners: HashMap::with_capacity(4),
		};
		Arc::new(Mutex::new(container))
	}

	pub fn listener(&self, interface: ListenerInterface) -> Result<&Box<dyn Listener>, Error> {
		self.listeners
			.get(&interface)
			.ok_or(Error::NoListener(format!("{}", interface)))
	}
}

pub trait Listener: Send + 'static {
	fn interface(&self) -> ListenerInterface;
	fn address(&self) -> String;

	fn publish(
		&self,
		slate: &VersionedSlate,
		to: &String,
		epicboxtxid: Option<&String>,
	) -> Result<(), Error>;

	fn cancel(&self, epicboxtxid: &String) -> Result<(), Error>;
	fn stop(self: Box<Self>) -> Result<(), Error>;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum ListenerInterface {
	Epicbox,
}
impl fmt::Display for ListenerInterface {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			ListenerInterface::Epicbox => write!(f, "Epicbox"),
		}
	}
}

impl<'a, P, L, C, K> EpicboxController<'a, P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub fn new(
		// TODO: check if container is required
		_container: Arc<Mutex<Container>>,
		publisher: P,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Option<SecretKey>,
		reconnections: &'a mut u32,
		tor_config: TorConfig,
	) -> Result<Self, Error> {
		Ok(Self {
			publisher,
			wallet,
			keychain_mask,
			reconnections,
			tor_config,
		})
	}

	fn process_tx_cancelled(&self, epicboxtxid: &str) -> Result<(), Error> {
		info!(
			"Processing relay-confirmed cancellation for epicboxtxid {}",
			epicboxtxid
		);

		match owner::cancel_epicbox_tx(
			self.wallet.clone(),
			self.keychain_mask.as_ref(),
			&epicboxtxid.to_string(),
			None, // Relay-confirmed path; never fall back to a Slate UUID.
		) {
			Ok(_) => {
				info!(
					"Transaction for epicboxtxid [{}] marked cancelled",
					epicboxtxid
				);
			}
			Err(e) => {
				warn!(
					"Local cancellation for epicboxtxid [{}] failed \
					 (it may already be finalized or cancelled): {:?}",
					epicboxtxid,
					e
				);
			}
		}

		Ok(())
	}

	fn process_incoming_slate(
		&self,
		address: Option<String>,
		slate: &mut Slate,
		_tx_proof: Option<&mut TxProof>,
	) -> Result<bool, Error> {
		// Case 1: Receiving a new transaction (not finalized)
		if slate.num_participants > slate.participant_data.len() {
			if slate.tx.inputs().is_empty() {
				// TODO: invoicing
			} else {
				info!("Receive new transaction (foreign::receive_tx)");
				wallet_lock!(self.wallet, w);
				match foreign::receive_tx(
					&mut **w,
					self.keychain_mask.as_ref(),
					&slate,
					None,
					None,
					address,
					false,
				) {
					Ok(ret_slate) => {
						*slate = ret_slate;
					}
					Err(e) => return Err(Error::EpicboxReceiveTx(format!("{:?}", e)).into()),
				};
			}
			return Ok(false);
		}

		// Case 2: Finalizing and posting the transaction
		info!("Finalize transaction (owner::finalize_tx)");
		let (finalized_slate, mut onion_addresses, node_client) = {
			wallet_lock!(self.wallet, w);
			let finalized_slate = owner::finalize_tx(&mut **w, self.keychain_mask.as_ref(), slate)?;
			// Get onion addresses and node client while wallet is still locked
			let onion_addresses = w.w2n_client().get_onion_addresses().unwrap_or_default();
			let node_client = w.w2n_client().clone();
			(finalized_slate, onion_addresses, node_client)
		};

		onion_addresses.shuffle(&mut rng());

		if let Some(tor_node_url) = onion_addresses.first() {
			if self.tor_config.use_tor_listener {
				info!("Post transaction to Tor address: {}", tor_node_url);
				match owner::post_tx_tor(&node_client, &finalized_slate.tx, tor_node_url) {
					Ok(_) => {}
					Err(_) => {
						owner::post_tx(&node_client, &finalized_slate.tx, false)?;
					}
				}
			} else {
				// Tor not enabled, use Dandelion/HTTP fallback
				owner::post_tx(&node_client, &finalized_slate.tx, false)?;
			}
		} else {
			owner::post_tx(&node_client, &finalized_slate.tx, false)?;
		}

		// --- Blocking mempool observation after post_tx ---
		let tx_slate_id = finalized_slate.id;
		let found = owner::wait_for_tx_in_mempool(
			self.wallet.clone(),
			self.keychain_mask.as_ref(),
			&tx_slate_id,
			1,   // poll every 1 second
			240, // up to 240 attempts (4 minutes)
		);
		if let Ok(true) = found {
			{
				wallet_lock!(self.wallet, w);
				owner::update_mempool_status(
					&mut **w,
					self.keychain_mask.as_ref(),
					&finalized_slate,
				)?;
			}
			info!(
				"Transaction with slate_id {} found in mempool and marked as TxSentMempool.",
				tx_slate_id
			);
		} else {
			warn!(
				"Transaction with slate_id {} not found in mempool after waiting.",
				tx_slate_id
			);
		}

		Ok(true)
	}
}
pub trait SubscriptionHandler: Send {
	fn on_slate(
		&self,
		from: &EpicboxAddress,
		slate: &VersionedSlate,
		proof: Option<&mut TxProof>,
		candidate_epicboxtxid: &String,
	) -> Result<(), Error>;

	fn on_post_slate_ack(
		&self,
		tx_slate_id: &Uuid,
		candidate_epicboxtxid: &String,
	) -> Result<String, Error>;

	fn on_tx_cancelled(&self, epicboxtxid: &String);
	fn on_close(&self, result: CloseReason);
}

impl<'a, P, L, C, K> SubscriptionHandler for EpicboxController<'a, P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn on_slate(
		&self,
		from: &EpicboxAddress,
		slate: &VersionedSlate,
		tx_proof: Option<&mut TxProof>,
		candidate_epicboxtxid: &String,
	) -> Result<(), Error> {
		let version = slate.version();
		let mut slate: Slate = slate.into();
		let tx_slate_id = slate.id.clone();

		if slate.num_participants > slate.participant_data.len() {
			debug!(
				"Slate [{}] received from [{}] for [{}] epics",
				slate.id,
				from,
				amount_to_hr_string(slate.amount, false)
			);
		} else {
			debug!(
				"Slate [{}] received back from [{}] for [{}] epics",
				slate.id,
				from,
				amount_to_hr_string(slate.amount, false)
			);
		}

		let is_finalized = self.process_incoming_slate(
			Some(from.to_string()),
			&mut slate,
			tx_proof,
		)?;

		// This owner helper must atomically preserve an existing stable ID and
		// return the effective value: either the pre-existing ID or the newly
		// stored candidate. Returning the effective value is required when a
		// legacy relay omits epicboxtxid on a later negotiation state.
		let stable_epicboxtxid = owner::set_tx_epicbox_msg_id_if_empty(
			self.wallet.clone(),
			self.keychain_mask.as_ref(),
			&tx_slate_id,
			candidate_epicboxtxid,
		)?;

		info!(
			"Stable epicboxtxid [{}] associated with Slate [{}]",
			stable_epicboxtxid,
			tx_slate_id
		);

		if !is_finalized {
			let response_slate = VersionedSlate::into_version(slate, version);

			// Carry the same stable transaction ID through every subsequent
			// Slate state. The broker also signs this ID independently.
			self.publisher.post_slate(
				&response_slate,
				from,
				false,
				Some(&stable_epicboxtxid),
			)?;
		} else {
			info!("Slate [{}] finalized successfully", tx_slate_id);
		}

		Ok(())
	}

	fn on_post_slate_ack(
		&self,
		tx_slate_id: &Uuid,
		candidate_epicboxtxid: &String,
	) -> Result<String, Error> {
		let stable_epicboxtxid = owner::set_tx_epicbox_msg_id_if_empty(
			self.wallet.clone(),
			self.keychain_mask.as_ref(),
			tx_slate_id,
			candidate_epicboxtxid,
		)?;

		info!(
			"Stored stable epicboxtxid [{}] for Slate [{}]",
			stable_epicboxtxid,
			tx_slate_id
		);

		Ok(stable_epicboxtxid)
	}

	fn on_tx_cancelled(&self, epicboxtxid: &String) {
		warn!(
			"Relay cancelled transaction for epicboxtxid {}",
			epicboxtxid
		);

		if let Err(e) = self.process_tx_cancelled(epicboxtxid) {
			error!(
				"Error handling transaction cancellation [{}]: {:?}",
				epicboxtxid,
				e
			);
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => {
				debug!("Listener stopped normally");
			}
			CloseReason::Abnormal(error) => {
				error!("{:?}", error.to_string());
			}
		}
	}
}

impl EpicboxSubscriber {
	fn start<P, L, C, K>(&mut self, handler: EpicboxController<P, L, C, K>) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		self.broker.subscribe(
			&self.address,
			&self.secret_key,
			handler,
			&self.wallet_mode,
			self.is_node_synced.clone(),
		)
	}

	fn stop(&self) {
		let _ = self.broker.stop();
	}
}

pub trait Publisher: Send {
	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		close_connection: bool,
		epicboxtxid: Option<&String>,
	) -> Result<(), Error>;

	fn cancel_tx(&self, epicboxtxid: &String) -> Result<(), Error>;
}

/// TODO: reduce to broker.
#[derive(Clone)]
pub struct EpicboxBroker {
	inner: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
	tx: Sender<BrokerEvent>,
	pending_post: Arc<Mutex<Option<PendingPost>>>,
	subscribed: Arc<AtomicBool>,
	stopping: Arc<AtomicBool>,
}

impl EpicboxBroker {
	/// Create a EpicboxBroker,
	pub fn new(
		inner: WebSocket<MaybeTlsStream<TcpStream>>,
		tx: Sender<BrokerEvent>,
	) -> Result<Self, Error> {
		Ok(Self {
			inner: Arc::new(Mutex::new(inner)),
			tx,
			pending_post: Arc::new(Mutex::new(None)),
			subscribed: Arc::new(AtomicBool::new(false)),
			stopping: Arc::new(AtomicBool::new(false)),
		})
	}
	/// Start a listener, passing received messages to the wallet api directly
	pub fn subscribe<P, L, C, K>(
		&mut self,
		address: &EpicboxAddress,
		secret_key: &SecretKey,
		handler: EpicboxController<P, L, C, K>,
		wallet_mode: &String,
		is_node_synced: Arc<AtomicBool>,
	) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let handler = Arc::new(Mutex::new(handler));
		let sender = self.inner.clone();
		let mut first_run = true;

		let mut client = EpicboxClient {
			sender,
			handler: handler.clone(),
			challenge: None,
			address: address.clone(),
			secret_key: secret_key.clone(),
			tx: self.tx.clone(),
		};

		let ver = EPICBOX_PROTOCOL_VERSION;
		let wallet_mode = wallet_mode;

		loop {
			if !is_node_synced.load(std::sync::atomic::Ordering::SeqCst) {
				warn!("Node not synced, pausing Epicbox message processing...");
				std::thread::sleep(std::time::Duration::from_secs(5));
				continue;
			}

			let read_result = client.sender.lock().read();

			// stop() sets this flag before trying to acquire the websocket mutex.
			// Check it after read() releases that mutex.
			if self
				.stopping
				.load(std::sync::atomic::Ordering::SeqCst)
			{
				debug!("Subscriber loop ending after stop()");
				handler.lock().on_close(CloseReason::Normal);
				break Ok(());
			}

			match read_result {
				Err(ErrorTungstenite::Io(ref e))
					if matches!(
						e.kind(),
						std::io::ErrorKind::WouldBlock
							| std::io::ErrorKind::TimedOut
					) =>
				{
					continue;
				}

				Err(e) => {
					*handler.lock().reconnections += 1;
					error!("Error reading Epicbox message: {:?}", e);
					handler.lock().on_close(CloseReason::Abnormal(
						Error::EpicboxWebsocketAbnormalTermination,
					));

					match client.sender.lock().close(None) {
						Ok(_) => error!("Epicbox client connection closed"),
						Err(close_error) => error!(
							"Error closing Epicbox client connection: {:?}",
							close_error
						),
					}

					break Err(Error::EpicboxWebsocketAbnormalTermination);
				}

				Ok(message) => match message {
					Message::Text(_) | Message::Binary(_) => {
						let response = match serde_json::from_str::<ProtocolResponseV2>(
							&message.to_string(),
						) {
							Ok(response) => response,
							Err(e) => {
								error!(
									"Could not parse Epicbox response: {:?}\nMessage was: {}",
									e,
									message.to_string()
								);
								continue;
							}
						};

						*handler.lock().reconnections = 0;

						match response {
							ProtocolResponseV2::Challenge { str } => {
								client.challenge = Some(str.clone());

								if first_run {
									client.client_details(wallet_mode.clone())?;
									first_run = false;
									info!("Starting Epicbox subscription...");
								}

								let signature =
									sign_challenge(&str, secret_key)?.to_hex();
								let request_sub = ProtocolRequestV2::Subscribe {
									address: client.address.public_key.to_string(),
									ver: ver.to_string(),
									signature,
								};

								match client.send(&request_sub) {
									Ok(()) => {
										self.subscribed.store(
											true,
											std::sync::atomic::Ordering::SeqCst,
										);
										let _ = client.tx.send(BrokerEvent::Subscribed);
									}
									Err(e) => {
										error!("Error sending Subscribe: {:?}", e);
									}
								}
							}

							ProtocolResponseV2::Slate {
								from,
								str,
								challenge: _challenge,
								signature,
								ver: _,
								epicboxmsgid,
								epicboxtxid,
							} => {
								let (slate, mut tx_proof) = match TxProof::from_response(
									from,
									str,
									signature,
									&client.secret_key,
									Some(&client.address),
								) {
									Ok(value) => value,
									Err(e) => {
										error!("{}", e);
										continue;
									}
								};

								// New relays provide the stable ID explicitly. For an old
								// relay, the per-message ID is a candidate used only if the
								// TxLogEntry does not already contain a stable ID.
								let candidate_epicboxtxid = epicboxtxid
									.unwrap_or_else(|| epicboxmsgid.clone());

								let proof_address = tx_proof.address.clone();
								if let Err(e) = client.handler.lock().on_slate(
									&proof_address,
									&slate,
									Some(&mut tx_proof),
									&candidate_epicboxtxid,
								) {
									error!(
										"Could not process/store Slate transaction [{}], \
										 message [{}]: {:?}",
										candidate_epicboxtxid,
										epicboxmsgid,
										e
									);

									// Do not send Made. The relay keeps the Slate and can
									// redeliver it after the local failure is resolved.
									continue;
								}

								let challenge = match client.challenge.as_ref() {
									Some(challenge) => challenge,
									None => {
										error!(
											"Received Slate before an Epicbox challenge"
										);
										continue;
									}
								};

								let signature =
									sign_challenge(challenge, secret_key)?.to_hex();
								let request_sub = ProtocolRequestV2::Subscribe {
									address: client.address.public_key.to_string(),
									ver: ver.to_string(),
									signature,
								};

								match client.send(&request_sub) {
									Ok(()) => {
										// Made always acknowledges the exact queued-message
										// identifier, never the stable transaction ID.
										if let Err(e) =
											client.made_send(epicboxmsgid.clone())
										{
											error!(
												"Error sending Made: {}",
												e
											);
										}
									}
									Err(e) => {
										error!(
											"Could not send Subscribe after Slate: {}",
											e
										);
									}
								}
							}

							ProtocolResponseV2::TransactionCancelled {
								epicboxtxid,
							} => {
								warn!(
									"Relay confirmed cancellation for epicboxtxid {}",
									epicboxtxid
								);

								client
									.handler
									.lock()
									.on_tx_cancelled(&epicboxtxid);

								let _ = client.tx.send(BrokerEvent::Cancelled {
									epicboxtxid: epicboxtxid.clone(),
								});

								if wallet_mode != "send" {
									if let Some(challenge) = client.challenge.as_ref() {
										let signature = sign_challenge(
											challenge,
											secret_key,
										)?
										.to_hex();

										let request_sub = ProtocolRequestV2::Subscribe {
											address: client
												.address
												.public_key
												.to_string(),
											ver: ver.to_string(),
											signature,
										};

										if let Err(e) = client.send(&request_sub) {
											error!(
												"Could not subscribe after cancellation: {}",
												e
											);
										}
									}
								}
							}

							ProtocolResponseV2::GetVersion { str } => {
								trace!("ProtocolResponseV2::GetVersion {}", str);
							}

							ProtocolResponseV2::Error {
								ref kind,
								description: _,
							} => match kind {
								ProtocolError::InvalidRequest => {
									error!(
										"Invalid request. Ensure the connected Epicbox \
										 supports the required protocol fields"
									);
								}
								_ => {
									error!("ProtocolResponseV2 error: {}", kind);
								}
							},

							ProtocolResponseV2::Ok {
								epicboxmsgid,
								epicboxtxid,
							} => {
								// Plain Ok responses are used by ClientDetails,
								// Subscribe, and Made. They must not consume a pending
								// PostSlate acknowledgement.
								if epicboxmsgid.is_none() && epicboxtxid.is_none() {
									debug!("Response Ok");
									continue;
								}

								let pending = self.pending_post.lock().take();
								let pending = match pending {
									Some(pending) => pending,
									None => {
										warn!(
											"Received relay IDs with no pending PostSlate: \
											 epicboxmsgid={:?}, epicboxtxid={:?}",
											epicboxmsgid,
											epicboxtxid
										);
										continue;
									}
								};

								if let (Some(expected), Some(returned)) =
									(pending.epicboxtxid.as_ref(), epicboxtxid.as_ref())
								{
									if expected != returned {
										warn!(
											"Relay returned epicboxtxid [{}], but the posted \
											 state carried stable ID [{}]; preserving [{}]",
											returned,
											expected,
											expected
										);
									}
								}

								// A later state must preserve its already-known ID. For
								// the initial state, prefer the relay's explicit stable ID
								// and fall back to the first per-message ID from an old relay.
								let candidate_epicboxtxid = pending
									.epicboxtxid
									.clone()
									.or(epicboxtxid)
									.or(epicboxmsgid);

								let candidate_epicboxtxid = match candidate_epicboxtxid {
									Some(id) => id,
									None => {
										warn!(
											"Relay acknowledged PostSlate without an Epicbox ID"
										);
										continue;
									}
								};

								let stable_epicboxtxid = match client
									.handler
									.lock()
									.on_post_slate_ack(
										&pending.slate_id,
										&candidate_epicboxtxid,
									) {
									Ok(id) => id,
									Err(e) => {
										error!(
											"Could not persist epicboxtxid [{}] for \
											 Slate [{}]: {:?}",
											candidate_epicboxtxid,
											pending.slate_id,
											e
										);
										continue;
									}
								};

								let _ = client.tx.send(BrokerEvent::PostAck {
									slate_id: pending.slate_id,
									epicboxtxid: stable_epicboxtxid,
								});
							}
						}
					}

					Message::Ping(_) => {}
					Message::Pong(_) => {}
					Message::Frame(_) => {}
					Message::Close(_) => {
						info!("Epicbox connection closed");
						handler.lock().on_close(CloseReason::Normal);
						let _ = client.sender.lock().close(None);
						break Ok(());
					}
				},
			}
		}
	}

	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		from: &EpicboxAddress,
		secret_key: &SecretKey,
		epicboxtxid: Option<&String>,
	) -> Result<(), Error> {
		let public_key = to.public_key()?;
		let secret_key_copy = secret_key.clone();

		let message = EncryptedMessage::new(
			serde_json::to_string(slate)?,
			to,
			&public_key,
			&secret_key_copy,
		)?;

		let message_ser = serde_json::to_string(&message)?;
		let signature = sign_challenge(&message_ser, secret_key)?.to_hex();

		let epicboxtxidsig = epicboxtxid
			.map(|id| {
				sign_challenge(id, secret_key)
					.map(|signature| signature.to_hex())
			})
			.transpose()?;

		let request = ProtocolRequest::PostSlate {
			from: from.stripped(),
			to: to.stripped(),
			str: message_ser,
			signature,
			epicboxtxid: epicboxtxid.cloned(),
			epicboxtxidsig,
		};

		let slate: Slate = slate.into();
		debug!("Starting to send Slate with id [{}]", slate.id);

		{
			let mut pending = self.pending_post.lock();
			if pending.is_some() {
				return Err(Error::EpicboxTungstenite(
					"Cannot post a second Slate while a relay acknowledgement is pending"
						.to_string()
						.into(),
				));
			}

			*pending = Some(PendingPost {
				slate_id: slate.id.clone(),
				epicboxtxid: epicboxtxid.cloned(),
			});
		}

		self.inner
			.lock()
			.send(Message::Text(
				serde_json::to_string(&request)?.into(),
			))
			.map_err(|e| {
				*self.pending_post.lock() = None;
				Error::EpicboxTungstenite(
					format!("Could not send PostSlate: {}", e).into(),
				)
			})?;

		debug!("Slate sent successfully");
		Ok(())
	}

	fn post_cancel_tx(
		&self,
		epicboxtxid: &String,
		from: &EpicboxAddress,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		if !self
			.subscribed
			.load(std::sync::atomic::Ordering::SeqCst)
		{
			return Err(Error::EpicboxTungstenite(
				"CancelTx requires an active Epicbox subscription on this connection"
					.to_string()
					.into(),
			));
		}

		let signature = sign_challenge(epicboxtxid, secret_key)?.to_hex();
		let request = ProtocolRequestV2::CancelTx {
			address: from.public_key.to_string(),
			epicboxtxid: epicboxtxid.clone(),
			signature,
		};

		debug!(
			"Sending CancelTx for epicboxtxid [{}]",
			epicboxtxid
		);

		self.inner
			.lock()
			.send(Message::Text(
				serde_json::to_string(&request)?.into(),
			))
			.map_err(|e| {
				Error::EpicboxTungstenite(
					format!("Could not send CancelTx: {}", e).into(),
				)
			})?;

		Ok(())
	}

	fn stop(&self) {
		self.stopping.store(true, std::sync::atomic::Ordering::SeqCst);
	}
}

struct EpicboxClient<'a, P, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
	P: Publisher,
{
	sender: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
	handler: Arc<Mutex<EpicboxController<'a, P, L, C, K>>>,
	challenge: Option<String>,
	address: EpicboxAddress,
	secret_key: SecretKey,
	tx: Sender<BrokerEvent>,
}

/// client with handler from ws package
impl<'a, P, L, C, K> EpicboxClient<'a, P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn made_send(&self, epicboxmsgid: String) -> Result<(), Error> {
		let signature = sign_challenge(&epicboxmsgid, &self.secret_key)?.to_hex();
		let request = ProtocolRequestV2::Made {
			address: self.address.public_key.to_string(),
			signature,
			epicboxmsgid,
			ver: EPICBOX_PROTOCOL_VERSION.to_string(),
		};

		match self.send(&request) {
			Ok(_) => {
				let _ = self.tx.send(BrokerEvent::Made);
				Ok(())
			}
			Err(e) => Err(Error::EpicboxTungstenite(
				format!("Could not send 'Made' request! {}", e).into(),
			)),
		}
	}

	fn client_details(&self, wallet_mode: String) -> Result<(), Error> {
		let version = env!("CARGO_PKG_VERSION");

		let request = ProtocolRequestV2::ClientDetails {
			wallet_version: version.to_string(),
			wallet_mode,
			protocol_version: EPICBOX_PROTOCOL_VERSION.to_string(),
		};

		match self.send(&request) {
			Ok(_) => Ok(()),
			Err(e) => Err(Error::EpicboxTungstenite(
				format!("Could not send 'ClientDetails' request! {}", e).into(),
			)),
		}
	}

	fn send(&self, request: &ProtocolRequestV2) -> Result<(), ErrorTungstenite> {
		let request = serde_json::to_string(&request).unwrap();
		self.sender.lock().send(Message::Text(request.into()))
	}
}

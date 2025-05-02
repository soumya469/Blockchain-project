#![allow(non_snake_case)]
#![no_std]
use soroban_sdk::{contract, contracttype, contractimpl, log, Env, Symbol, String, symbol_short, Address, BytesN, Vec};

// Recovery data structure with encrypted backup information and security settings
#[contracttype]
#[derive(Clone)]
pub struct RecoveryData {
    pub user_address: Address,           // User's blockchain address
    pub encrypted_backup: BytesN<32>,    // Encrypted 2FA recovery seed/key
    pub recovery_nonce: BytesN<16>,      // Nonce used for encryption
    pub timelock_expiry: u64,            // Timestamp when recovery can be completed
    pub recovery_initiated: bool,        // Flag indicating if recovery is in progress
    pub recovery_attempts: u32,          // Number of recovery attempts made
    pub max_attempts: u32,               // Maximum allowed recovery attempts
}

// Event data for recovery attempts
#[contracttype]
#[derive(Clone)]
pub struct RecoveryEvent {
    pub user_address: Address,
    pub timestamp: u64,
    pub successful: bool,
}

// For mapping user addresses to their recovery data
#[contracttype]
pub enum DataKey {
    UserRecovery(Address),             // Maps user address to RecoveryData
}

// Contract data storage constants
const ADMIN: Symbol = symbol_short!("ADMIN");
const DEFAULT_TIMELOCK: Symbol = symbol_short!("DFLT_LOCK");

#[contract]
pub struct TwoFactorBackupContract;

#[contractimpl]
impl TwoFactorBackupContract {
    // Initialize the contract with admin address and default timelock period
    pub fn initialize(env: Env, admin: Address, default_timelock_period: u64) {
        // Ensure the contract is not already initialized
        if env.storage().instance().has(&ADMIN) {
            panic!("Contract already initialized");
        }
        
        // Set the admin address and default timelock period
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&DEFAULT_TIMELOCK, &default_timelock_period);
        
        log!(&env, "Contract initialized with admin: {}", admin);
    }
    
    // Register 2FA backup data for a user
    pub fn register_backup(
        env: Env, 
        user: Address,
        encrypted_backup: BytesN<32>,
        recovery_nonce: BytesN<16>,
        max_attempts: u32
    ) {
        // Authorize the user
        user.require_auth();
        
        // Check if user already has backup data
        let key = DataKey::UserRecovery(user.clone());
        if env.storage().instance().has(&key) {
            panic!("User already has backup data registered");
        }
        
        // Get default timelock period
        let default_timelock: u64 = env.storage().instance().get(&DEFAULT_TIMELOCK).unwrap();
        
        // Create recovery data
        let recovery_data = RecoveryData {
            user_address: user.clone(),
            encrypted_backup: encrypted_backup,
            recovery_nonce: recovery_nonce,
            timelock_expiry: 0, // Not in recovery mode initially
            recovery_initiated: false,
            recovery_attempts: 0,
            max_attempts: max_attempts,
        };
        
        // Store the recovery data
        env.storage().instance().set(&key, &recovery_data);
        
        env.storage().instance().extend_ttl(5000, 5000);
        
        log!(&env, "2FA backup registered for user: {}", user);
    }
    
    // Initiate the recovery process
    pub fn initiate_recovery(env: Env, user: Address) {
        // Authorize the user
        user.require_auth();
        
        let key = DataKey::UserRecovery(user.clone());
        
        // Check if user has backup data
        if !env.storage().instance().has(&key) {
            panic!("No backup data found for user");
        }
        
        // Get user's recovery data
        let mut recovery_data: RecoveryData = env.storage().instance().get(&key).unwrap();
        
        // Check if recovery is already initiated
        if recovery_data.recovery_initiated {
            panic!("Recovery already in progress");
        }
        
        // Get the default timelock period
        let default_timelock: u64 = env.storage().instance().get(&DEFAULT_TIMELOCK).unwrap();
        
        // Calculate timelock expiry
        let current_time = env.ledger().timestamp();
        recovery_data.timelock_expiry = current_time + default_timelock;
        recovery_data.recovery_initiated = true;
        
        // Update recovery data
        env.storage().instance().set(&key, &recovery_data);
        
        log!(&env, "Recovery initiated for user: {}, expiry: {}", user, recovery_data.timelock_expiry);
    }
    
    // Complete the recovery process and retrieve the backup data
    pub fn complete_recovery(env: Env, user: Address) -> RecoveryData {
        // Authorize the user
        user.require_auth();
        
        let key = DataKey::UserRecovery(user.clone());
        
        // Check if user has backup data
        if !env.storage().instance().has(&key) {
            panic!("No backup data found for user");
        }
        
        // Get user's recovery data
        let mut recovery_data: RecoveryData = env.storage().instance().get(&key).unwrap();
        
        // Check if recovery is initiated
        if !recovery_data.recovery_initiated {
            panic!("Recovery not initiated");
        }
        
        // Check timelock period
        let current_time = env.ledger().timestamp();
        if current_time < recovery_data.timelock_expiry {
            panic!("Timelock period has not expired yet");
        }
        
        // Check attempts
        recovery_data.recovery_attempts += 1;
        if recovery_data.recovery_attempts > recovery_data.max_attempts {
            panic!("Maximum recovery attempts exceeded");
        }
        
        // Reset recovery status
        recovery_data.recovery_initiated = false;
        recovery_data.timelock_expiry = 0;
        
        // Update recovery data
        env.storage().instance().set(&key, &recovery_data);
        
        // Log recovery event
        let recovery_event = RecoveryEvent {
            user_address: user.clone(),
            timestamp: current_time,
            successful: true,
        };
        
        log!(&env, "Recovery completed successfully for user: {}", user);
        
        // Return the recovery data to the user
        return recovery_data;
    }
}
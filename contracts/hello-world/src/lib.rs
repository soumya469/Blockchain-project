#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Symbol, symbol_short};

// Structure to represent an order
#[contracttype]
#[derive(Clone)]
pub struct Order {
    pub order_id: u64,
    pub buyer: Address,
    pub product: String,
    pub is_fulfilled: bool,
    pub timestamp: u64,
}

// Enum for storage keys
#[contracttype]
pub enum OrderKey {
    Order(u64),
    OrderCount,
}

#[contract]
pub struct OrderFulfillmentVerifier;

#[contractimpl]
impl OrderFulfillmentVerifier {
    // Create a new order
    pub fn create_order(env: Env, buyer: Address, product: String) -> u64 {
        let mut count: u64 = env.storage().instance().get(&OrderKey::OrderCount).unwrap_or(0);
        count += 1;

        let new_order = Order {
            order_id: count,
            buyer,
            product,
            is_fulfilled: false,
            timestamp: env.ledger().timestamp(),
        };

        env.storage().instance().set(&OrderKey::Order(count), &new_order);
        env.storage().instance().set(&OrderKey::OrderCount, &count);

        count
    }

    // Mark order as fulfilled
    pub fn fulfill_order(env: Env, order_id: u64) {
        let mut order: Order = env.storage().instance().get(&OrderKey::Order(order_id)).expect("Order not found");

        if order.is_fulfilled {
            panic!("Order already fulfilled");
        }

        order.is_fulfilled = true;
        env.storage().instance().set(&OrderKey::Order(order_id), &order);
    }

    // View an order
    pub fn get_order(env: Env, order_id: u64) -> Order {
        env.storage().instance().get(&OrderKey::Order(order_id)).expect("Order not found")
    }
}

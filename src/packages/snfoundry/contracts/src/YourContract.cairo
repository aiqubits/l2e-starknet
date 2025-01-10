use starknet::ContractAddress;

#[starknet::interface]
pub trait IYourContract<TContractState> {
    fn check_ft_address(self: @TContractState, ft_address: ContractAddress) -> bool;
    fn check_admin_address(self: @TContractState, admin_address: ContractAddress)  -> bool;
    fn check_auth_address(self: @TContractState, auth_address: ContractAddress)  -> bool;
    fn get_rewards_for_spender(self: @TContractState, spender: ContractAddress) -> (u256, u256, u256);

    fn approve_for_spender(
        ref self:TContractState,
        spender: ContractAddress,
        eth_amount: u256,
        strk_amount: u256,
        ft_amount: u256,
        ft_address: Option<ContractAddress>,
    ) -> Option<felt252>;
    fn transfer_balances_from(
        ref self: TContractState,
        owner: ContractAddress,
        password: felt252,
        ft_address: Option<ContractAddress>,
    ) -> bool;

    fn add_admin_address(ref self: TContractState, new_admin_address: ContractAddress);
    fn add_auth_token_owner(ref self: TContractState, new_owner_address: ContractAddress);
    fn add_ft_address(ref self: TContractState, new_ft_address: ContractAddress);

    // init trait
    fn greeting(self: @TContractState) -> ByteArray;
    fn set_greeting(ref self: TContractState, new_greeting: ByteArray, amount_eth: u256);
    fn withdraw(ref self: TContractState);
    fn premium(self: @TContractState) -> bool;
}

#[starknet::contract]
mod YourContract {
    use starknet::event::EventEmitter;
use openzeppelin_access::ownable::OwnableComponent;
    use openzeppelin_token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::storage::Map;
    use starknet::{ContractAddress, contract_address_const};
    use starknet::{get_caller_address, get_contract_address, get_block_timestamp};
    use super::{IYourContract};
    use core::poseidon::PoseidonTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};


    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    const ETH_CONTRACT_ADDRESS: felt252 =
        0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7;

    const STARKNET_TOKEN_ADDRESS: felt252 =
        0x4718f5a0Fc34cC1AF16A1cdee98fFB20C31f5cD61D6Ab07201858f4287c938D;

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // init event
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        GreetingChanged: GreetingChanged,
        // l2e event
        L2eEvent: L2eEvent,
    }

    #[derive(Drop, starknet::Event)]
    struct L2eEvent {
        #[key]
        caller: ContractAddress,
        #[key]
        result: ByteArray,
    }

    #[derive(Drop, starknet::Event)]
    struct GreetingChanged {
        #[key]
        greeting_setter: ContractAddress,
        #[key]
        new_greeting: ByteArray,
        premium: bool,
        value: u256,
    }

    #[storage]
    struct Storage {
        // spenderid -> <(ownerid, eth balance, strk balance, token balance)> total balance can be mutli stage claim.
        balances: Map<ContractAddress, (ContractAddress, u256, u256, u256, felt252)>,
        ft_address: Map<ContractAddress, felt252>,
        admin_address: Map<ContractAddress, felt252>,
        auth_token_owner: Map<ContractAddress, felt252>,

        // init storage
        greeting: ByteArray,
        premium: bool,
        total_counter: u256,
        user_greeting_counter: Map<ContractAddress, u256>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, ft_address: ContractAddress) {
        self.balances.write(owner, (owner, 0, 0, 0, 0));
        self.ft_address.write(ft_address, 1);
        self.admin_address.write(owner, 1);
        self.auth_token_owner.write(owner, 1);

        // init construct
        self.greeting.write("Building Unstoppable Apps!!!");
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl YourContractImpl of IYourContract<ContractState> {
        fn check_ft_address(self: @ContractState, ft_address: ContractAddress) -> bool {
            if self.ft_address.read(ft_address) != 1 {
                return true;
            }
            false
        }

        fn check_admin_address(self: @ContractState, admin_address: ContractAddress)  -> bool {
            if self.admin_address.read(admin_address) != 1 {
                return true;
            }
            false
        }

        fn check_auth_address(self: @ContractState, auth_address: ContractAddress)  -> bool {
            if self.admin_address.read(auth_address) != 1 {
                return true;
            } 
            false
        }

        fn get_rewards_for_spender(self: @ContractState, spender: ContractAddress) -> (u256, u256, u256) {
            let (_owner, eth_balance, strk_balance, token_balance, _hash) = self.balances.read(spender);
            (eth_balance, strk_balance, token_balance)
        }

        // First Transfer ETH Strk FT Token to l2e contract.
        fn approve_for_spender(
            ref self: ContractState,
            spender: ContractAddress,
            eth_amount: u256,
            strk_amount: u256,
            ft_amount: u256,
            ft_address: Option<ContractAddress>,
        ) -> Option<felt252> {
            let (owner, eth_balance, strk_balance, token_balance, hash) = self.balances.read(spender);
            let caller = get_caller_address();
            assert!(owner == caller, "Approve failed, Invalid owner address.");
            assert!(eth_amount > 0 || strk_amount > 0 || ft_amount > 0, "Approve failed, Invalid amount argument.");
            assert!(hash == 0, "Approve failed, Rewards already exist, Awaiting claim.");

            // genertate random number for owner
            let current_time = get_block_timestamp();
            let hash: felt252 = PoseidonTrait::new().update_with((current_time, spender)).finalize();

            // Update spender balance
            self.balances.write(spender, (owner, eth_balance + eth_amount, strk_balance + strk_amount, token_balance + ft_amount, hash));
            
            self.emit(
                L2eEvent {
                    caller: get_caller_address(),
                    result: "Approve successful, one password generated.",
                }
            );
            Option::Some(hash)
        }

        fn transfer_balances_from(
            ref self: ContractState,
            owner: ContractAddress,
            password: felt252,
            ft_address: Option<ContractAddress>,
        ) -> bool { 
            let spender = get_caller_address();
            let (owner_address, eth_balance, strk_balance, token_balance, hash) = self.balances.read(spender);
            assert!(owner_address == owner, "Claim failed, Invalid owner address.");
            assert!(hash == password, "Claim failed, Invalid password.");
            assert!((( eth_balance + strk_balance + token_balance ) != 0), "Claim failed, No rewards to claim.");

            let eth_contract_address = contract_address_const::<ETH_CONTRACT_ADDRESS>();
            let eth_dispatcher = IERC20Dispatcher { contract_address: eth_contract_address };
            let strk_contract_address = contract_address_const::<STARKNET_TOKEN_ADDRESS>();
            let strk_dispatcher = IERC20Dispatcher { contract_address: strk_contract_address };

            // Transfer ETH amount from owner to spender
            eth_dispatcher.transfer_from(owner, spender, eth_balance);

            // Transfer Strk amount from owner to spender
            strk_dispatcher.transfer_from(owner, spender, strk_balance);

            // Transfer FT amount from owner to spender
            if let Option::Some(ft_address) = ft_address {
                let ft_dispatcher = IERC20Dispatcher { contract_address: ft_address };
                ft_dispatcher.transfer_from(owner, spender, token_balance);
            }

            // Update spender balance
            self.balances.write(spender, (owner, 0, 0, 0, 0));

            self.emit(
                L2eEvent {
                    caller: get_caller_address(),
                    result: "Claim successful, Transfer balances completed.",
                }
            );
            true
        }
    
        fn add_admin_address(ref self: ContractState, new_admin_address: ContractAddress) {
            self.ownable.assert_only_owner();
            assert!(self.check_admin_address(new_admin_address) == false, "Admin address add failed, Address already exists.");

            self.admin_address.write(new_admin_address, 1);
            self.emit(
                L2eEvent {
                    caller: get_caller_address(),
                    result: "Admin address added successfully.",
                }
            );
         }
        fn add_auth_token_owner(ref self: ContractState, new_owner_address: ContractAddress) { 
            let caller = get_caller_address();
            assert!(self.check_admin_address(caller), "Owner address add failed, Only admin can add owner address.");
            assert!(!self.check_auth_address(new_owner_address), "Owner address add failed, Address already exists.");

            self.auth_token_owner.write(new_owner_address, 1);
            self.emit(
                L2eEvent {
                    caller: get_caller_address(),
                    result: "Owner address added successfully.",
                }
            );
        }

        fn add_ft_address(ref self: ContractState, new_ft_address: ContractAddress) { 
            let caller = get_caller_address();
            assert!(self.check_admin_address(caller) || self.check_auth_address(caller), "FT address add failed, Only Admin or AuthTokenOwner can add FT address.");
            assert!(!self.check_ft_address(new_ft_address), "FT address add failed, Address already exists.");

            self.ft_address.write(new_ft_address, 1);
            self.emit(
                L2eEvent {
                    caller: get_caller_address(),
                    result: "FT address added successfully.",
                }
            );
         }  


        // init contract
        fn greeting(self: @ContractState) -> ByteArray {
            self.greeting.read()
        }
        fn set_greeting(ref self: ContractState, new_greeting: ByteArray, amount_eth: u256) {
            self.greeting.write(new_greeting);
            self.total_counter.write(self.total_counter.read() + 1);
            let user_counter = self.user_greeting_counter.read(get_caller_address());
            self.user_greeting_counter.write(get_caller_address(), user_counter + 1);

            if amount_eth > 0 {
                // In `Debug Contract` or UI implementation call `approve` on ETH contract before
                // invoke fn set_greeting()
                let eth_contract_address = contract_address_const::<ETH_CONTRACT_ADDRESS>();
                let eth_dispatcher = IERC20Dispatcher { contract_address: eth_contract_address };
                eth_dispatcher
                    .transfer_from(get_caller_address(), get_contract_address(), amount_eth);
                self.premium.write(true);
            } else {
                self.premium.write(false);
            }
            self
                .emit(
                    GreetingChanged {
                        greeting_setter: get_caller_address(),
                        new_greeting: self.greeting.read(),
                        premium: true,
                        value: 100,
                    },
                );
        }
        fn withdraw(ref self: ContractState) {
            self.ownable.assert_only_owner();
            let eth_contract_address = contract_address_const::<ETH_CONTRACT_ADDRESS>();
            let eth_dispatcher = IERC20Dispatcher { contract_address: eth_contract_address };
            let balance = eth_dispatcher.balance_of(get_contract_address());
            eth_dispatcher.transfer(self.ownable.owner(), balance);
        }
        fn premium(self: @ContractState) -> bool {
            self.premium.read()
        }
    }
}

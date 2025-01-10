/**
 * This file is autogenerated by Scaffold-Stark.
 * You should not edit it manually or your changes might be overwritten.
 */

const deployedContracts = {
  devnet: {
    YourContract: {
      address:
        "0x6ad65deeb09bb3b14b36d58803b549a8ed135ac65b11dc2d365e41b1a533fac",
      abi: [
        {
          type: "impl",
          name: "YourContractImpl",
          interface_name: "contracts::YourContract::IYourContract",
        },
        {
          type: "enum",
          name: "core::bool",
          variants: [
            {
              name: "False",
              type: "()",
            },
            {
              name: "True",
              type: "()",
            },
          ],
        },
        {
          type: "struct",
          name: "core::integer::u256",
          members: [
            {
              name: "low",
              type: "core::integer::u128",
            },
            {
              name: "high",
              type: "core::integer::u128",
            },
          ],
        },
        {
          type: "enum",
          name: "core::option::Option::<core::starknet::contract_address::ContractAddress>",
          variants: [
            {
              name: "Some",
              type: "core::starknet::contract_address::ContractAddress",
            },
            {
              name: "None",
              type: "()",
            },
          ],
        },
        {
          type: "enum",
          name: "core::option::Option::<core::felt252>",
          variants: [
            {
              name: "Some",
              type: "core::felt252",
            },
            {
              name: "None",
              type: "()",
            },
          ],
        },
        {
          type: "struct",
          name: "core::byte_array::ByteArray",
          members: [
            {
              name: "data",
              type: "core::array::Array::<core::bytes_31::bytes31>",
            },
            {
              name: "pending_word",
              type: "core::felt252",
            },
            {
              name: "pending_word_len",
              type: "core::integer::u32",
            },
          ],
        },
        {
          type: "interface",
          name: "contracts::YourContract::IYourContract",
          items: [
            {
              type: "function",
              name: "check_ft_address",
              inputs: [
                {
                  name: "ft_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "check_admin_address",
              inputs: [
                {
                  name: "admin_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "check_auth_address",
              inputs: [
                {
                  name: "auth_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "get_rewards_for_spender",
              inputs: [
                {
                  name: "spender",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "(core::integer::u256, core::integer::u256, core::integer::u256)",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "approve_for_spender",
              inputs: [
                {
                  name: "spender",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "eth_amount",
                  type: "core::integer::u256",
                },
                {
                  name: "strk_amount",
                  type: "core::integer::u256",
                },
                {
                  name: "ft_amount",
                  type: "core::integer::u256",
                },
                {
                  name: "ft_address",
                  type: "core::option::Option::<core::starknet::contract_address::ContractAddress>",
                },
              ],
              outputs: [
                {
                  type: "core::option::Option::<core::felt252>",
                },
              ],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "transfer_balances_from",
              inputs: [
                {
                  name: "owner",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "password",
                  type: "core::felt252",
                },
                {
                  name: "ft_address",
                  type: "core::option::Option::<core::starknet::contract_address::ContractAddress>",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "add_admin_address",
              inputs: [
                {
                  name: "new_admin_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "add_auth_token_owner",
              inputs: [
                {
                  name: "new_owner_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "add_ft_address",
              inputs: [
                {
                  name: "new_ft_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "greeting",
              inputs: [],
              outputs: [
                {
                  type: "core::byte_array::ByteArray",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "set_greeting",
              inputs: [
                {
                  name: "new_greeting",
                  type: "core::byte_array::ByteArray",
                },
                {
                  name: "amount_eth",
                  type: "core::integer::u256",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "withdraw",
              inputs: [],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "premium",
              inputs: [],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
          ],
        },
        {
          type: "impl",
          name: "OwnableImpl",
          interface_name: "openzeppelin_access::ownable::interface::IOwnable",
        },
        {
          type: "interface",
          name: "openzeppelin_access::ownable::interface::IOwnable",
          items: [
            {
              type: "function",
              name: "owner",
              inputs: [],
              outputs: [
                {
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "transfer_ownership",
              inputs: [
                {
                  name: "new_owner",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "renounce_ownership",
              inputs: [],
              outputs: [],
              state_mutability: "external",
            },
          ],
        },
        {
          type: "constructor",
          name: "constructor",
          inputs: [
            {
              name: "owner",
              type: "core::starknet::contract_address::ContractAddress",
            },
            {
              name: "ft_address",
              type: "core::starknet::contract_address::ContractAddress",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferred",
          kind: "struct",
          members: [
            {
              name: "previous_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "new_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferStarted",
          kind: "struct",
          members: [
            {
              name: "previous_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "new_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_access::ownable::ownable::OwnableComponent::Event",
          kind: "enum",
          variants: [
            {
              name: "OwnershipTransferred",
              type: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferred",
              kind: "nested",
            },
            {
              name: "OwnershipTransferStarted",
              type: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferStarted",
              kind: "nested",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::YourContract::YourContract::GreetingChanged",
          kind: "struct",
          members: [
            {
              name: "greeting_setter",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "new_greeting",
              type: "core::byte_array::ByteArray",
              kind: "key",
            },
            {
              name: "premium",
              type: "core::bool",
              kind: "data",
            },
            {
              name: "value",
              type: "core::integer::u256",
              kind: "data",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::YourContract::YourContract::L2eEvent",
          kind: "struct",
          members: [
            {
              name: "caller",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "result",
              type: "core::byte_array::ByteArray",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::YourContract::YourContract::Event",
          kind: "enum",
          variants: [
            {
              name: "OwnableEvent",
              type: "openzeppelin_access::ownable::ownable::OwnableComponent::Event",
              kind: "flat",
            },
            {
              name: "GreetingChanged",
              type: "contracts::YourContract::YourContract::GreetingChanged",
              kind: "nested",
            },
            {
              name: "L2eEvent",
              type: "contracts::YourContract::YourContract::L2eEvent",
              kind: "nested",
            },
          ],
        },
      ],
      classHash:
        "0x4e881db1286914119f2c900d19ab8fea1811614fdfa86d5f7539f7bc1c83e9c",
    },
  },
  sepolia: {
    "L2E-Starknet": {
      address:
        "0x18d80f7d9004fcd165fc5beae65235fe74aac193d7de2d3d48ddc10cd6471dd",
      abi: [
        {
          type: "impl",
          name: "YourContractImpl",
          interface_name: "contracts::YourContract::IYourContract",
        },
        {
          type: "enum",
          name: "core::bool",
          variants: [
            {
              name: "False",
              type: "()",
            },
            {
              name: "True",
              type: "()",
            },
          ],
        },
        {
          type: "struct",
          name: "core::integer::u256",
          members: [
            {
              name: "low",
              type: "core::integer::u128",
            },
            {
              name: "high",
              type: "core::integer::u128",
            },
          ],
        },
        {
          type: "enum",
          name: "core::option::Option::<core::starknet::contract_address::ContractAddress>",
          variants: [
            {
              name: "Some",
              type: "core::starknet::contract_address::ContractAddress",
            },
            {
              name: "None",
              type: "()",
            },
          ],
        },
        {
          type: "enum",
          name: "core::option::Option::<core::felt252>",
          variants: [
            {
              name: "Some",
              type: "core::felt252",
            },
            {
              name: "None",
              type: "()",
            },
          ],
        },
        {
          type: "struct",
          name: "core::byte_array::ByteArray",
          members: [
            {
              name: "data",
              type: "core::array::Array::<core::bytes_31::bytes31>",
            },
            {
              name: "pending_word",
              type: "core::felt252",
            },
            {
              name: "pending_word_len",
              type: "core::integer::u32",
            },
          ],
        },
        {
          type: "interface",
          name: "contracts::YourContract::IYourContract",
          items: [
            {
              type: "function",
              name: "check_ft_address",
              inputs: [
                {
                  name: "ft_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "check_admin_address",
              inputs: [
                {
                  name: "admin_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "check_auth_address",
              inputs: [
                {
                  name: "auth_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "get_rewards_for_spender",
              inputs: [
                {
                  name: "spender",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "(core::integer::u256, core::integer::u256, core::integer::u256)",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "approve_for_spender",
              inputs: [
                {
                  name: "spender",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "eth_amount",
                  type: "core::integer::u256",
                },
                {
                  name: "strk_amount",
                  type: "core::integer::u256",
                },
                {
                  name: "ft_amount",
                  type: "core::integer::u256",
                },
                {
                  name: "ft_address",
                  type: "core::option::Option::<core::starknet::contract_address::ContractAddress>",
                },
              ],
              outputs: [
                {
                  type: "core::option::Option::<core::felt252>",
                },
              ],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "transfer_balances_from",
              inputs: [
                {
                  name: "owner",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "password",
                  type: "core::felt252",
                },
                {
                  name: "ft_address",
                  type: "core::option::Option::<core::starknet::contract_address::ContractAddress>",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "add_admin_address",
              inputs: [
                {
                  name: "new_admin_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "add_auth_token_owner",
              inputs: [
                {
                  name: "new_owner_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "add_ft_address",
              inputs: [
                {
                  name: "new_ft_address",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "greeting",
              inputs: [],
              outputs: [
                {
                  type: "core::byte_array::ByteArray",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "set_greeting",
              inputs: [
                {
                  name: "new_greeting",
                  type: "core::byte_array::ByteArray",
                },
                {
                  name: "amount_eth",
                  type: "core::integer::u256",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "withdraw",
              inputs: [],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "premium",
              inputs: [],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
          ],
        },
        {
          type: "impl",
          name: "OwnableImpl",
          interface_name: "openzeppelin_access::ownable::interface::IOwnable",
        },
        {
          type: "interface",
          name: "openzeppelin_access::ownable::interface::IOwnable",
          items: [
            {
              type: "function",
              name: "owner",
              inputs: [],
              outputs: [
                {
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "transfer_ownership",
              inputs: [
                {
                  name: "new_owner",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "renounce_ownership",
              inputs: [],
              outputs: [],
              state_mutability: "external",
            },
          ],
        },
        {
          type: "constructor",
          name: "constructor",
          inputs: [
            {
              name: "owner",
              type: "core::starknet::contract_address::ContractAddress",
            },
            {
              name: "ft_address",
              type: "core::starknet::contract_address::ContractAddress",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferred",
          kind: "struct",
          members: [
            {
              name: "previous_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "new_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferStarted",
          kind: "struct",
          members: [
            {
              name: "previous_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "new_owner",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_access::ownable::ownable::OwnableComponent::Event",
          kind: "enum",
          variants: [
            {
              name: "OwnershipTransferred",
              type: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferred",
              kind: "nested",
            },
            {
              name: "OwnershipTransferStarted",
              type: "openzeppelin_access::ownable::ownable::OwnableComponent::OwnershipTransferStarted",
              kind: "nested",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::YourContract::YourContract::GreetingChanged",
          kind: "struct",
          members: [
            {
              name: "greeting_setter",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "new_greeting",
              type: "core::byte_array::ByteArray",
              kind: "key",
            },
            {
              name: "premium",
              type: "core::bool",
              kind: "data",
            },
            {
              name: "value",
              type: "core::integer::u256",
              kind: "data",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::YourContract::YourContract::L2eEvent",
          kind: "struct",
          members: [
            {
              name: "caller",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "key",
            },
            {
              name: "result",
              type: "core::byte_array::ByteArray",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::YourContract::YourContract::Event",
          kind: "enum",
          variants: [
            {
              name: "OwnableEvent",
              type: "openzeppelin_access::ownable::ownable::OwnableComponent::Event",
              kind: "flat",
            },
            {
              name: "GreetingChanged",
              type: "contracts::YourContract::YourContract::GreetingChanged",
              kind: "nested",
            },
            {
              name: "L2eEvent",
              type: "contracts::YourContract::YourContract::L2eEvent",
              kind: "nested",
            },
          ],
        },
      ],
      classHash:
        "0x77728848258b1b85ada0dd8fe5a37612b319759b3894620a9d0760e91349f2e",
    },
  },
} as const;

export default deployedContracts;
# BEP-2: Tokens on BNB Beacon Chain

- [BEP-2: Tokens on BNB Beacon Chain](#bep-2-tokens-on-bnb-beacon-chain)
  - [1.  Summary](#1--summary)
  - [2.  Abstract](#2--abstract)
  - [3.  Status](#3--status)
  - [4.  Motivation](#4--motivation)
  - [5.  Specification](#5--specification)
    - [5.1 Native Token on BNB Beacon Chain: BNB](#51-native-token-on-bnb-beacon-chain-bnb)
    - [5.2 Token Properties](#52-token-properties)
    - [5.3 Token Management Operation](#53-token-management-operation)
      - [5.3.1 Issue token](#531-issue-token)
      - [5.3.2 Transfer Tokens](#532-transfer-tokens)
      - [5.3.3  Freeze Tokens](#533-freeze-tokens)
      - [5.3.4  Unfreeze Tokens](#534-unfreeze-tokens)
      - [5.3.5 Mint Tokens](#535-mint-tokens)
      - [5.3.6 Burn Tokens](#536-burn-tokens)
  - [6. License](#6-license)

## 1.  Summary

This BEP describes a proposal for token management on the BNB Beacon Chain.

## 2.  Abstract

BEP-2 Proposal describes a common set of rules for token management within the BNB Beacon Chain ecosystem. It introduces the following details of a token on BNB Beacon Chain:

- What information makes a token on BNB Beacon Chain
- What actions can be performed on a token on BNB Beacon Chain

## 3.  Status

This BEP is already implemented, and it has been improved via [BEP87](./BEP87.md).

## 4.  Motivation

Design and issue asset on the BNB Beacon Chain, as the basic economic foundations of the blockchain.

## 5.  Specification

### 5.1 Native Token on BNB Beacon Chain: BNB

The BNB Beacon Token, BNB, is the native asset on BNB Beacon Chain and created within Genesis Block. As the native asset, BNB would be used for fees (gas) and staking on BNB Beacon Chain. BNB was an ERC20 token, but after BNB Beacon Chain is live, all BNB ERC20 tokens are swapped for BNB token on BNB Beacon Chain. All users who hold BNB ERC20 tokens can deposit them to Binance.com, and upon withdrawal, the new BNB Beacon Chain native tokens will be sent to their new addresses.

### 5.2 Token Properties

- Source Address: Source Address is the owner of the issued token.

- Token Name: Token Name represents the long name of the token - e.g. "MyToken".

- Symbol: Symbol is the identifier of the newly issued token.

- Total Supply: Total supply will be the total number of issued tokens.

- Mintable: Mintable means whether this token can be minted in the future, which would increase the total supply of the token

### 5.3 Token Management Operation

#### 5.3.1 Issue token

Issuing token is to create a new token on BNB Beacon Chain. The new token represents ownership of something new, and can also peg to existing tokens from any other blockchains.

**Data Structure for Issue Operation**: A data structure is needed to represent the new token:

| **Field**    | **Type** | **Description**                                              |
| :------------ | :-------- | :------------------------------------------------------------ |
| Name         | string   | Name of the newly issued asset, limited to 32 unicode characters,  e.g. "ABCcoin" |
| Symbol       | string   | The length of the string for representing this asset is between 3 and 8 alphanumeric characters and is case insensitive. "B" suffixed symbol is also allowed for pegging to those tokens already exist on other chains. The symbol is suffixed with the first 3 bytes of the issue transaction hash to remove a constraint of requiring unique token names. The native token, BNB, does not require this suffix. |
| Total Supply | int64    | The total supply for this token can have a maximum of 8 digits of decimal and is boosted by 1e8 in order to store as int64. The amount before boosting should not exceed 90 billion. |
| Owner        | Address  | The initial issuer of this token, the BNB balance of issuer should be more than the fee for issuing tokens |
| Mintable     | Boolean  | Whether this token could be minted(increased) after the initial issuing |

The data in all the above fields are not changeable after the Issue Transaction, except “Total Supply” can be changed via “Mint” or “Burn” operations.

**Symbol Convention:**

[Symbol][B]-[Suffix]

Explanations: Suffix is the first 3 bytes of the issue transaction’s hash. It helps to remove the constraint of requiring unique token names. If this token pegs to an existing blockchain, there should be an additional suffix of “B”.

**Issue Process:**

- Issuer signed an issue transaction and make it broadcasted to one of BNB Beacon Chain nodes
- This BNB Beacon Chain node will check this transaction. If there is no error, then this transaction will be broadcasted to other BNB Beacon Chain nodes
- Issue transaction is committed on the blockchain by block proposer
- Validators will verify the constraints on total supply and symbol and deduct the fee from issuer’s account
- New token’s symbol is generated based on the transaction hash. It is added to the issuer’s address and token info is saved on the BNB Beacon Chain

#### 5.3.2 Transfer Tokens

Transfer transaction is to send tokens from input addresses to output addresses.

**Message Structure for Transfer Operation**: A data structure is needed to represent the transfer operation between addresses.

| **Field** | **Type** | **Description**              |
| :--------- | :-------- | :---------------------------- |
| Input     | []Input  | A set of transaction inputs  |
| Output    | []Output | A set of transaction outputs |

**Input Data Structure:**

| **Field** | **Type** | **Description**                                              |
| :--------- | :-------- | :------------------------------------------------------------ |
| Address   | Address  | Address for token holders                                    |
| Coins     | []Coin   | A set of sorted coins, one per currency. The symbols of coins are in descending order. |

**Output Data Structure:**

| **Field** | **Type** | **Description**                                              |
| :--------- | :-------- | :------------------------------------------------------------ |
| Address   | Address  | Address for token holders                                    |
| Coins     | []Coin   | A set of sorted coins, one per currency. The denominations of coins are in descending order. |

**Coin Structure:**

| **Field** | **Type** | **Description**                                              |
| :--------- | :-------- | :------------------------------------------------------------ |
| Denom     | string   | The symbol of a token                                        |
| Amount    | int64    | The amount is positive and can have a maximum of 8 digits of decimal and is boosted by 1e8 in order to store as int64. |

**Transfer Process:**

- Transferer initiators sign a transfer transaction and make it broadcasted to one of BNB Beacon Chain nodes
- The BNB Beacon Chain node will check this transaction. If there is no error, then this transaction will be broadcasted to other BNB Beacon Chain nodes
- Transfer transaction is committed on the blockchain by block proposer
- Validators will verify the constraints on balance. The transfer tokens and fee will be deducted from the address of the transaction initiators.
- Add the tokens to the destination addresses

#### 5.3.3 Freeze Tokens

A BNB Beacon Chain user could freeze some amount of tokens in his own address. The freeze transaction will lock his fund, thus this portion of tokens could not be used for the transactions, such as: creating orders, transferring to another account, paying fees and etc.

**Data Structure** **for Freeze Operation**: A data structure is needed to represent the freeze operation

| **Field** | **Type** | **Description**                                              |
| :--------- | :-------- | :------------------------------------------------------------ |
| Symbol    | string   | The symbol should belong to an existing token,e.g. NNB-B90   |
| Amount    | int64    | Frozen amount for this token can have a maximum of 8 digits of decimal, and the value is boosted by 1e8 to store in an int64. This amount should be less than its balance |

**Freeze Process:**

- Address-holder signed a freeze transaction and make it broadcasted to one of BNB Beacon Chain nodes
- The BNB Beacon Chain node will check this transaction. If there is no error, then this transaction will be broadcasted to other BNB Beacon Chain nodes
- Freeze transaction is committed on the blockchain by block proposer
- Validators will verify the transaction initiator’s balance is no less than the frozen amount. The fee will be deducted from the transaction initiator’s address.
- This amount of tokens in the address of the transaction initiator will be moved from balance to frozen.

#### 5.3.4 Unfreeze Tokens

Unfreezing is to unlock some of the frozen tokens in the user's account and make them liquid again.

**Data Structure** **for Unfreeze Operation**: A data structure is needed to represent the freeze/unfreeze operation

| **Field** | **Type** | **Description**                                              |
| :--------- | :-------- | :------------------------------------------------------------ |
| Symbol    | string   | The symbol should belong to an existing token,e.g. NNB-B90   |
| Amount    | int64    | The unfreeze amount can have a maximum of 8 digits of decimal, and the value is boosted by 1e8 to store in an int64. This amount should be no less than the frozen amount |

**Unfreeze Process:**

- Address-holder signed an unfreeze transaction and make it broadcasted to one of BNB Beacon Chain nodes
- The BNB Beacon Chain node will check this transaction. If there is no error, then this transaction will be broadcasted to other BNB Beacon Chain nodes
- Unfreeze transaction is committed on the blockchain by block proposer
- Validators will verify the transaction initiator’s frozen balance is no less than the required amount. The fee will be deducted from the address of the transaction source.
- This amount of token will be moved from frozen to balance in the transaction initiator’s address.

#### 5.3.5 Mint Tokens

Mint transaction is to increase the total supply of a mintable token. The transaction initiator must be the token owner.

**Data Structure** **for Mint Operation**: A data structure is needed to represent the mint operation

| **Field** | **Type** | **Description**                                              |
| :--------- | :-------- | :------------------------------------------------------------ |
| Symbol    | string   | The symbol should belong to an existing mintable token, e.g. NNB-B90 |
| Amount    | int64    | Added supply for this token can have a maximum of 8 digits of decimal, and the value is boosted by 1e8 to store in an int64. The amount before boosting operation should be less than 90 billion after mint. |

**Mint Process:**

- Token owner signs a mint transaction and makes it broadcasted to one of BNB Beacon Chain nodes
- The BNB Beacon Chain node will check this transaction. If there is no error, then this transaction will be broadcasted to other BNB Beacon Chain nodes
- Mint transaction is committed on the blockchain by block proposer
- Validators will verify the constraints on whether the token is mintable and whether the bumped total supply will pass the limit. Then increase its total supply and deduct the fee from the address of the token owner
- Newly minted tokens are added to the address of the token owner and token info is updated on the BNB Beacon Chain

#### 5.3.6 Burn Tokens

Burn transaction is to reduce the total supply of a token. The transaction initiator must be the token owner.

**Data Structure** **for Burn Operation**: A data structure is needed to represent the burn operation

| **Field** | **Type** | **Description**                                              |
| :--------- | :-------- | :------------------------------------------------------------ |
| Symbol    | string   | The symbol should belong to an existing token,e.g. NNB-B90   |
| Amount    | int64    | Burnt supply for this token can have a maximum of 8 digits of decimal, and the value is boosted by 1e8 to store in an int64. The amount should be less than its total supply |

**Burn Process:**

- Token owner signs a burn transaction and makes it broadcasted to one of BNB Beacon Chain nodes
- The BNB Beacon Chain node will check this transaction. If there is no error, then this transaction will be broadcasted to other BNB Beacon Chain nodes
- Burn transaction is committed on the blockchain by block proposer
- Validators will verify the constraints if the token’s supply is no less than the required amount, and then it decreases the total supply and deducts the fee from the address of the token owner
- Burned tokens are deducted from the address of the token owner and token info is updated on the BNB Beacon Chain

## 6. License

The content is licensed under [CC0](https://creativecommons.org/publicdomain/zero/1.0/).

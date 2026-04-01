# Payment Flow Diagrams

Visual diagrams of the Cashu NFC card payment flows. These can be rendered by GitHub, VS Code, or any Mermaid-compatible viewer.

## End-to-End Flow

```mermaid
flowchart TB
    subgraph TOP_UP["🌐 Top-Up Phase (Online)"]
        direction LR
        U1[👤 User opens wallet app]
        U2[📱 App connects to Mint]
        U3[💰 Mint issues Cashu tokens]
        U4[📶 App writes tokens to card via NFC]
        U1 --> U2 --> U3 --> U4
    end
    
    subgraph PAYMENT["📴 Payment Phase (Offline)"]
        direction LR
        P1[👤 Customer taps card]
        P2[🏪 Terminal reads tokens]
        P3[✍️ Card signs spend authorization]
        P4[✅ Payment complete]
        P1 --> P2 --> P3 --> P4
    end
    
    subgraph SETTLE["⏰ Settlement Phase (Later)"]
        direction LR
        S1[🏪 Terminal goes online]
        S2[🏦 Submits tokens to Mint]
        S3[💵 Mint redeems tokens]
        S1 --> S2 --> S3
    end
    
    TOP_UP --> PAYMENT --> SETTLE
```

## Detailed Payment Sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as 💳 NFC Card
    participant T as 🏪 Terminal (POS)
    participant M as 🏦 Cashu Mint
    
    rect rgb(240, 248, 255)
        Note over C,T: Offline Payment (No internet required)
        
        T->>C: SELECT APPLICATION
        C-->>T: OK (version info)
        
        T->>C: GET_BALANCE
        C-->>T: 50,000 sats
        
        Note over T: Customer wants to pay 5,000 sats
        
        T->>C: GET_SLOT_STATUS
        C-->>T: [slot statuses]
        
        T->>C: GET_PROOF (slot with enough value)
        C-->>T: Token data (keyset, amount, secret, signature)
        
        T->>C: SPEND_PROOF (slot index, message)
        Note over C: ⚠️ Token permanently marked SPENT
        C-->>T: Schnorr signature
        
        Note over T: ✅ Payment accepted!<br/>Token stored for later redemption
    end
    
    rect rgb(255, 248, 240)
        Note over T,M: Later: Settlement (Online)
        
        T->>M: POST /melt (tokens + signatures)
        M-->>T: 200 OK (redeemed)
        Note over M: Tokens invalidated at mint
    end
```

## Top-Up (Provisioning) Sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as 📱 User's Phone
    participant C as 💳 NFC Card
    participant M as 🏦 Cashu Mint
    
    rect rgb(240, 255, 240)
        Note over U,M: Online: Get tokens from Mint
        
        U->>M: POST /mint (amount: 10,000 sats)
        M-->>U: Cashu tokens (locked to card pubkey)
    end
    
    rect rgb(255, 255, 240)
        Note over U,C: NFC: Write tokens to card
        
        U->>C: SELECT APPLICATION
        C-->>U: OK
        
        U->>C: GET_PUBKEY
        C-->>U: Card's public key (for P2PK locking)
        
        U->>C: VERIFY_PIN (if PIN is set)
        C-->>U: OK
        
        U->>C: CLEAR_SPENT (reclaim old slots)
        C-->>U: 3 slots freed
        
        loop For each token
            U->>C: LOAD_PROOF (token data)
            C-->>U: Slot index assigned
        end
        
        U->>C: GET_BALANCE
        C-->>U: 60,000 sats (previous 50k + new 10k)
        
        Note over U: ✅ Top-up complete!
    end
```

## Card States

```mermaid
stateDiagram-v2
    [*] --> Empty: Card installed
    
    Empty --> Funded: LOAD_PROOF (tokens added)
    Funded --> Funded: More LOAD_PROOF
    Funded --> PartiallySpent: SPEND_PROOF
    PartiallySpent --> PartiallySpent: More SPEND_PROOF
    PartiallySpent --> AllSpent: Last token spent
    
    AllSpent --> Empty: CLEAR_SPENT
    PartiallySpent --> Funded: CLEAR_SPENT + LOAD_PROOF
    
    note right of Funded: Card has unspent tokens
    note right of AllSpent: All tokens spent,<br/>slots need clearing
```

## Proof Slot Lifecycle

```mermaid
stateDiagram-v2
    direction LR
    
    [*] --> EMPTY: Slot initialized
    EMPTY --> UNSPENT: LOAD_PROOF
    UNSPENT --> SPENT: SPEND_PROOF
    SPENT --> EMPTY: CLEAR_SPENT
    
    note right of EMPTY: status = 0x00
    note right of UNSPENT: status = 0x01
    note right of SPENT: status = 0x02<br/>(irreversible without CLEAR)
```

---

## Embedding These Diagrams

### In GitHub README/Markdown

GitHub natively renders Mermaid in markdown files. Just paste the code blocks.

### In a Website

```html
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true});</script>

<div class="mermaid">
  flowchart LR
    A[Card] -->|tap| B[Terminal]
</div>
```

### Export as PNG/SVG

Use the [Mermaid Live Editor](https://mermaid.live/) to export diagrams as images.

/**
 * OCNCC Billing Engine OpenAPI Specification.
 * OpenAPI 3.0 specification for the OCNCC Billing Engine API
 *
 * © COPYRIGHT: Blue Bridge Software Ltd - 2026
 * Author: Tony Craven
 */

'use strict';

function buildSpec(serverUrl, serverDescription) {
  return {
    openapi: '3.0.3',
    info: {
      title: 'OCNCC Billing Engine Client API',
      description: `REST API for communicating with Oracle OCNCC Billing Engines via the Escher protocol.\n\n` +
        `## Message Formats\n` +
        `All endpoints accept both **raw** (4-char symbol keys like \`TYPE\`, \`HEAD\`, \`BODY\`) ` +
        `and **friendly** (human-readable keys like \`FOX Type\`, \`Header\`, \`Body\`) JSON formats.\n\n` +
        `Responses include both formats by default. Use the \`format\` query parameter to select one.\n\n` +
        `## Billing Engine Routing\n` +
        `Messages are routed to the appropriate billing engine via the \`billingEngineId\` parameter ` +
        `or the \`SVID\` / \`BE Server ID\` field in the message header.\n\n` +
        `## Connection Failover\n` +
        `Each billing engine has a primary and optional secondary connection. ` +
        `New requests always go to the primary first. If the primary is unavailable, ` +
        `the request fails over to the secondary automatically.`,
      version: '1.0.0',
      contact: { name: 'Blue Bridge Software Ltd' }
    },
    servers: [{ url: serverUrl, description: serverDescription }],
    tags: [
      { name: 'Generic', description: 'Send any Escher message' },
      { name: 'Wallet Info', description: 'Wallet information queries' },
      { name: 'Reservations', description: 'Time-based reservation lifecycle' },
      { name: 'Named Events', description: 'Named event charging and reservations' },
      { name: 'Amount Reservations', description: 'Amount-based reservation lifecycle' },
      { name: 'Direct Charges', description: 'Direct amount and tariffed charges' },
      { name: 'Rating', description: 'Rate queries' },
      { name: 'Wallet Management', description: 'Create, update, delete wallets' },
      { name: 'Recharging', description: 'Wallet recharge operations' },
      { name: 'Vouchers', description: 'Voucher operations' },
      { name: 'Administration', description: 'Administrative operations' },
      { name: 'Status', description: 'Connection status and health' },
      { name: 'Configuration', description: 'Runtime configuration management' }
    ],
    paths: {
      // ---- Generic ----
      '/api/send': {
        post: {
          tags: ['Generic'],
          summary: 'Send generic Escher message',
          description: 'Send any valid Escher protocol message to a billing engine. Accepts both raw and friendly JSON formats.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/preferredEngine' },
            { $ref: '#/components/parameters/responseFormat' },
            { $ref: '#/components/parameters/isNewDialog' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: {
            200: { $ref: '#/components/responses/EscherResponse' },
            400: { $ref: '#/components/responses/Error400' },
            502: { $ref: '#/components/responses/Error502' },
            504: { $ref: '#/components/responses/Error504' }
          }
        }
      },

      // ---- Wallet Info ----
      '/api/wallet-info': {
        post: {
          tags: ['Wallet Info'],
          summary: 'Wallet Info (WI)',
          description: 'Query wallet information including balances.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/WalletInfoMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/wallet-state-info': {
        post: {
          tags: ['Wallet Info'],
          summary: 'Wallet State Info (WSI)',
          description: 'Query wallet state information.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/WalletStateInfoMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Time-Based Reservations ----
      '/api/initial-reservation': {
        post: {
          tags: ['Reservations'],
          summary: 'Initial Reservation (IR)',
          description: 'Start a new time-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/subsequent-reservation': {
        post: {
          tags: ['Reservations'],
          summary: 'Subsequent Reservation (SR)',
          description: 'Extend an existing time-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/commit-reservation': {
        post: {
          tags: ['Reservations'],
          summary: 'Commit Reservation (CR)',
          description: 'Commit and finalise a time-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/revoke-reservation': {
        post: {
          tags: ['Reservations'],
          summary: 'Revoke Reservation (RR)',
          description: 'Revoke a time-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Named Events ----
      '/api/named-event': {
        post: {
          tags: ['Named Events'],
          summary: 'Named Event (NE)',
          description: 'Apply a named event charge.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/initial-named-event-reservation': {
        post: {
          tags: ['Named Events'],
          summary: 'Initial Named Event Reservation (INER)',
          description: 'Start a named event reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/subsequent-named-event-reservation': {
        post: {
          tags: ['Named Events'],
          summary: 'Subsequent Named Event Reservation (SNER)',
          description: 'Extend a named event reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/confirm-named-event-reservation': {
        post: {
          tags: ['Named Events'],
          summary: 'Confirm Named Event Reservation (CNER)',
          description: 'Confirm a named event reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/revoke-named-event-reservation': {
        post: {
          tags: ['Named Events'],
          summary: 'Revoke Named Event Reservation (RNER)',
          description: 'Revoke a named event reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Amount Reservations ----
      '/api/initial-amount-reservation': {
        post: {
          tags: ['Amount Reservations'],
          summary: 'Initial Amount Reservation (IARR)',
          description: 'Start a new amount-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/subsequent-amount-reservation': {
        post: {
          tags: ['Amount Reservations'],
          summary: 'Subsequent Amount Reservation (SARR)',
          description: 'Extend an existing amount-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/confirm-amount-reservation': {
        post: {
          tags: ['Amount Reservations'],
          summary: 'Confirm Amount Reservation (CARR)',
          description: 'Confirm and finalise an amount-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/revoke-amount-reservation': {
        post: {
          tags: ['Amount Reservations'],
          summary: 'Revoke Amount Reservation (RARR)',
          description: 'Revoke an amount-based reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Direct Charges ----
      '/api/apply-tariffed-charge': {
        post: {
          tags: ['Direct Charges'],
          summary: 'Apply Tariffed Charge (ATC)',
          description: 'Apply a tariffed charge to a wallet.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/direct-amount': {
        post: {
          tags: ['Direct Charges'],
          summary: 'Direct Amount (DA)',
          description: 'Apply a direct debit or credit.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Rating ----
      '/api/unit-second-rate': {
        post: {
          tags: ['Rating'],
          summary: 'Unit Second Rate (USR)',
          description: 'Query unit/second rate.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/named-event-rate': {
        post: {
          tags: ['Rating'],
          summary: 'Named Event Rate (NER)',
          description: 'Query named event rate.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Wallet Management ----
      '/api/wallet-create': {
        post: {
          tags: ['Wallet Management'],
          summary: 'Wallet Create (WC)',
          description: 'Create a new wallet.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/WalletCreateMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/wallet-update': {
        post: {
          tags: ['Wallet Management'],
          summary: 'Wallet Update (WU)',
          description: 'Update wallet properties.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/WalletUpdateMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/wallet-delete': {
        post: {
          tags: ['Wallet Management'],
          summary: 'Wallet Delete (WD)',
          description: 'Delete a wallet.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/WalletDeleteMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Recharging ----
      '/api/wallet-general-recharge': {
        post: {
          tags: ['Recharging'],
          summary: 'Wallet General Recharge (WGR)',
          description: 'Recharge a wallet with specified balance amounts.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Vouchers ----
      '/api/voucher-info': {
        post: {
          tags: ['Vouchers'],
          summary: 'Voucher Info (VI)',
          description: 'Query voucher information.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/voucher-redeem': {
        post: {
          tags: ['Vouchers'],
          summary: 'Voucher Redeem (VR)',
          description: 'Redeem a voucher.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/commit-voucher-redeem': {
        post: {
          tags: ['Vouchers'],
          summary: 'Commit Voucher Redeem (CVR)',
          description: 'Commit a voucher redemption.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/revoke-voucher-redeem': {
        post: {
          tags: ['Vouchers'],
          summary: 'Revoke Voucher Redeem (RVR)',
          description: 'Revoke a voucher redemption.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/voucher-redeem-wallet': {
        post: {
          tags: ['Vouchers'],
          summary: 'Voucher Redeem Wallet (VRW)',
          description: 'Redeem a voucher to a specific wallet.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/voucher-update': {
        post: {
          tags: ['Vouchers'],
          summary: 'Voucher Update (VU)',
          description: 'Update voucher state.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/voucher-type-recharge': {
        post: {
          tags: ['Vouchers'],
          summary: 'Voucher Type Recharge (VTR)',
          description: 'Recharge using a voucher type.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/voucher-type-recharge-confirm': {
        post: {
          tags: ['Vouchers'],
          summary: 'Voucher Type Recharge Confirm (VTRC)',
          description: 'Confirm voucher type recharge.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Administration ----
      '/api/bad-pin': {
        post: {
          tags: ['Administration'],
          summary: 'Bad PIN (BPIN)',
          description: 'Report a bad PIN attempt.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/reload-mfile': {
        post: {
          tags: ['Administration'],
          summary: 'Reload MFile (LDMF)',
          description: 'Trigger MFile reload on the billing engine.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/wallet-reservations-info': {
        post: {
          tags: ['Administration'],
          summary: 'Wallet Reservations Info (WRI)',
          description: 'Query active reservations on a wallet.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/wallet-reservation-end': {
        post: {
          tags: ['Administration'],
          summary: 'Wallet Reservation End (WRE)',
          description: 'Force-end a reservation.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },
      '/api/merge-wallets': {
        post: {
          tags: ['Administration'],
          summary: 'Merge Wallets (MGW)',
          description: 'Merge two wallets.',
          parameters: [
            { $ref: '#/components/parameters/billingEngineId' },
            { $ref: '#/components/parameters/responseFormat' }
          ],
          requestBody: { $ref: '#/components/requestBodies/GenericMessage' },
          responses: { 200: { $ref: '#/components/responses/EscherResponse' }, 400: { $ref: '#/components/responses/Error400' }, 502: { $ref: '#/components/responses/Error502' }, 504: { $ref: '#/components/responses/Error504' } }
        }
      },

      // ---- Status & Config ----
      '/api/status': {
        get: {
          tags: ['Status'],
          summary: 'Get status of all billing engine connections',
          responses: {
            200: {
              description: 'Connection status for all billing engines',
              content: { 'application/json': { schema: { type: 'object' } } }
            }
          }
        }
      },
      '/api/status/{engineId}': {
        get: {
          tags: ['Status'],
          summary: 'Get status of a specific billing engine',
          parameters: [
            { name: 'engineId', in: 'path', required: true, schema: { type: 'integer' } }
          ],
          responses: {
            200: {
              description: 'Connection status for the billing engine',
              content: { 'application/json': { schema: { type: 'object' } } }
            },
            404: { description: 'Billing engine not found' }
          }
        }
      },
      '/api/stats': {
        get: {
          tags: ['Status'],
          summary: 'Get API usage statistics',
          parameters: [
            { name: 'hours', in: 'query', description: 'Number of hours to return', required: false, schema: { type: 'integer', default: 24 } }
          ],
          responses: {
            200: {
              description: 'Usage statistics aggregated in rolling periods',
              content: { 'application/json': { schema: { type: 'object' } } }
            }
          }
        }
      },
      '/api/config': {
        get: {
          tags: ['Configuration'],
          summary: 'Get current configuration',
          responses: {
            200: {
              description: 'Current configuration',
              content: { 'application/json': { schema: { type: 'object' } } }
            }
          }
        }
      },
      '/api/config/engines': {
        post: {
          tags: ['Configuration'],
          summary: 'Add or update a billing engine',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['id', 'primary'],
                  properties: {
                    id: { type: 'integer', description: 'Billing engine ID', example: 1 },
                    primary: {
                      type: 'object',
                      required: ['ip', 'port'],
                      properties: {
                        ip: { type: 'string', example: '10.0.0.1' },
                        port: { type: 'integer', example: 1500 }
                      }
                    },
                    secondary: {
                      type: 'object',
                      properties: {
                        ip: { type: 'string', example: '10.0.0.2' },
                        port: { type: 'integer', example: 1500 }
                      }
                    }
                  }
                }
              }
            }
          },
          responses: {
            200: { description: 'Engine added/updated' },
            400: { $ref: '#/components/responses/Error400' }
          }
        },
        delete: {
          tags: ['Configuration'],
          summary: 'Remove a billing engine',
          parameters: [
            { name: 'id', in: 'query', required: true, schema: { type: 'integer' } }
          ],
          responses: {
            200: { description: 'Engine removed' },
            404: { description: 'Engine not found' }
          }
        }
      }
    },
    components: {
      parameters: {
        billingEngineId: {
          name: 'billingEngineId',
          in: 'query',
          description: 'Billing engine ID. Overrides SVID in the message header.',
          required: false,
          schema: { type: 'integer' }
        },
        responseFormat: {
          name: 'format',
          in: 'query',
          description: 'Response format: raw (4-char symbols), friendly (human-readable), or both (default)',
          required: false,
          schema: { type: 'string', enum: ['raw', 'friendly', 'both'], default: 'raw' }
        },
        isNewDialog: {
          name: 'isNewDialog',
          in: 'query',
          description: 'Whether this is a new dialog (always tries primary first). Default: true.',
          required: false,
          schema: { type: 'boolean', default: true }
        },
        preferredEngine: {
          name: 'preferredEngine',
          in: 'query',
          description: 'Preferred target engine. Defaults to primary. Falls back if unavailable.',
          required: false,
          schema: { type: 'string', enum: ['primary', 'secondary'], default: 'primary' }
        }
      },
      requestBodies: {
        GenericMessage: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                description: 'Escher message in raw or friendly JSON format',
                example: {
                  "_comment": "WI - Wallet Info Request",
                  "ACTN": "REQ ",
                  "TYPE": "WI  ",
                  "HEAD": {
                    "CMID": 1001,
                    "DATE": "~date:1774035629",
                    "DUP ": 0,
                    "SVID": 1,
                    "USEC": 247024,
                    "VER ": 100
                  },
                  "BODY": {
                    "WALT": 12345,
                    "WALR": "ACC001:1",
                    "BTYP": 2,
                    "BUNT": 1,
                    "UCUR": 840
                  }
                }
              }
            }
          }
        },
        WalletCreateMessage: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                description: 'Wallet Create message in raw or friendly JSON format',
                example: {
                  "_comment": "WC - Wallet Create Request",
                  "ACTN": "REQ ",
                  "TYPE": "WC  ",
                  "HEAD": {
                    "CMID": 1001,
                    "DATE": "~date:1774035629",
                    "DUP ": 0,
                    "SVID": 1,
                    "USEC": 247024,
                    "VER ": 100
                  },
                  "BODY": {
                    "ABAL": [
                      {
                        "BKTS": [
                          {
                            "EXPR": null,
                            "ID  ": 0,
                            "VAL ": 100000
                          }
                        ],
                        "BTYP": 1,
                        "LIMT": "DEBT"
                      },
                      {
                        "BKTS": [
                          {
                            "EXPR": null,
                            "ID  ": 0,
                            "STDT": "~date:1774035629",
                            "VAL ": 100000
                          }
                        ],
                        "BTYP": 2,
                        "LIMT": "DEBT"
                      }
                    ],
                    "ACTV": null,
                    "ACTY": 1,
                    "CLI ": "07917321654",
                    "EXPR": null,
                    "LUSE": null,
                    "MAXC": 1,
                    "STAT": "PREU",
                    "WALT": 22,
                    "WTYP": 1
                  }
                }
              }
            }
          }
        },
        WalletDeleteMessage: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                description: 'Wallet Delete message in raw or friendly JSON format',
                example: {
                  "_comment": "WD - Wallet Delete Request",
                  "ACTN": "REQ ",
                  "TYPE": "WD  ",
                  "HEAD": {
                    "CMID": 1001,
                    "DATE": "~date:1774035629",
                    "DUP ": 0,
                    "SVID": 1,
                    "USEC": 247024,
                    "VER ": 100
                  },
                  "BODY": {
                    "WALT": 12345
                  }
                }
              }
            }
          }
        },
        WalletInfoMessage: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                description: 'Wallet Info message in raw or friendly JSON format',
                example: {
                  "_comment": "WI - Wallet Info Request",
                  "ACTN": "REQ ",
                  "TYPE": "WI  ",
                  "HEAD": {
                    "CMID": 1001,
                    "DATE": "~date:1774035629",
                    "DUP ": 0,
                    "SVID": 1,
                    "USEC": 247024,
                    "VER ": 100
                  },
                  "BODY": {
                    "WALT": 12345
                  }
                }
              }
            }
          }
        },
        WalletStateInfoMessage: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                description: 'Wallet State Info message in raw or friendly JSON format',
                example: {
                  "_comment": "WSI - Wallet State Info Request",
                  "ACTN": "REQ ",
                  "TYPE": "WSI ",
                  "HEAD": {
                    "CMID": 1001,
                    "DATE": "~date:1774035629",
                    "DUP ": 0,
                    "SVID": 1,
                    "USEC": 247024,
                    "VER ": 100
                  },
                  "BODY": {
                    "WALT": 12345
                  }
                }
              }
            }
          }
        },
        WalletUpdateMessage: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                description: 'Wallet Update message in raw or friendly JSON format',
                example: {
                  "_comment": "WU - Wallet Update Request",
                  "ACTN": "REQ ",
                  "TYPE": "WU  ",
                  "HEAD": {
                    "CMID": 1001,
                    "DATE": "1774035629",
                    "DUP ": 0,
                    "SVID": 1,
                    "USEC": 247024,
                    "VER ": 100
                  },
                  "BODY": {
                    "WALT": 12345,
                    "ABAL": [
                      {
                        "BTYP": 1,
                        "LIMT": "DEBT",
                        "BKTS": [
                          {
                            "ID  ": 0,
                            "VAL ": 100000,
                            "EXPR": null
                          },
                        ]
                      },
                      {
                        "BTYP": 2,
                        "LIMT": "DEBT",
                        "BKTS": [
                          {
                            "ID  ": 0,
                            "VAL ": 100000,
                            "EXPR": null,
                            "STDT": "1774035629"
                          },
                        ]
                      }
                    ],
                    "ACTY": 1,
                    "AREF": 4,
                    "CDR ": [
                      {
                        "TAG ": "USER",
                        "VAL ": "SU"
                      },
                      {
                        "TAG ": "TERMINAL",
                        "VAL ": "127.0.0.1"
                      },
                      {
                        "TAG ": "WALLET_TYPE",
                        "VAL ": 1
                      }
                    ],
                    "WALT": 4,
                  }
                }
              }
            }
          }
        },
      },
      responses: {
        EscherResponse: {
          description: 'Billing engine response',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  format: { type: 'string', enum: ['raw', 'friendly', 'both'] },
                  raw: { type: 'object', description: 'Response with raw 4-char symbol keys' },
                  friendly: { type: 'object', description: 'Response with human-readable keys' },
                  message: { type: 'object', description: 'Response (when format is raw or friendly)' }
                }
              }
            }
          }
        },
        Error400: {
          description: 'Bad request',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string' }
                }
              }
            }
          }
        },
        Error502: {
          description: 'Billing engine connection error',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string' }
                }
              }
            }
          }
        },
        Error504: {
          description: 'Billing engine timeout',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string' }
                }
              }
            }
          }
        }
      }
    }
  };
}

module.exports = buildSpec;

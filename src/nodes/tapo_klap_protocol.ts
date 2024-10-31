'use strict'

// Import modules
import {TextEncoder, promisify} from 'node:util';
import {Cipher, KeyObject, createHash, createCipheriv, createDecipheriv, webcrypto, KeyPairKeyObjectResult, generateKeyPair, privateDecrypt, constants} from 'node:crypto';
import axios, {AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse} from 'axios';
import http from 'node:http';
import https from 'node:https';
import {v4 as uuidv4} from 'uuid';
import find from 'local-devices';

// Type aliases used
export type Json_T = {[any: string]: any};
export type Cause = {error_code: number, message: string, agent: string};
export type Method_Exp = (any) => any;

// Global constants for internal use
const RSA_CIPHER_ALGORITHM = 'rsa';
const AES_CIPHER_ALGORITHM = 'aes-128-cbc';
const PASSPHRASE = "top secret";
const TP_SESSION_COOKIE_NAME = "TP_SESSIONID";
const TP_TEST_USER = "test@tp-link.net";
const TP_TEST_PASSWORD = "test";
const CLOUD_URL = "https://eu-wap.tplinkcloud.com";
const MAX_RETRIES_GUESS = 3;
const AXIOS_TIMEOUT = 1000;

// Constants for supported Energy devices
export const supportEnergyUsage = ["P110","P115","KP125M"];

// Constants for Error 
export enum ErrorCode {
    // ----------GENERAL ERROR (1-99)-------------------
    ERROR_AXIOS_ERROR = 1,
    ERROR_TAPRES_JSON_INVALID = 2,
    ERROR_AXIOS_FORBID = 3,
    GENERIC_ERROR = 99,
    // ----------ENCRIPTION ERROR (101-199)-------------
    ERROR_KL_ENCRYPT_FMT = 101,
    ERROR_KL_ENCRYPT_IV_LENGTH = 102,
    ERROR_CH_UNABLE_KEYS = 103,
    ERROR_SNOW_WORKER_ID = 104,
    ERROR_SNOW_DATA_CENTER_ID = 105,
    ERROR_SNOW_INVALID_TIME_ID = 106,
    // ----------SESSION POST ERROR (201-299)-----------
    ERROR_aSP_bAX_REQ_ERR = 201,
    ERROR_aSP_bAX_REQ_FORBID = 202,
    ERROR_aSP_bAX_INVALID_URL = 203,
    // ----------SEND REQUEST ERROR (301-399)-----------
    ERROR_aSR_bSR_RET_ERR = 301,
    ERROR_aSR_bSR_MAX_RET = 302,
    ERROR_aSR_bSP_REQ_ERR = 303,
    ERROR_aSR_bSP_REJ = 304,
    ERROR_aSR_DEV_FORBID = 305,
    ERROR_aSR_DEV_GENERAL = 399,
    // ----------HANDSHAKE ERROR (401-499)--------------
    ERROR_aPH2_bSP_HSK_ERROR = 401,
    ERROR_aPH1_bSP_HSK_ERROR = 402,
    ERROR_aPH2_bSP_HSK_REJ = 411,
    ERROR_aPH_bSP_HSK_REJ = 412,
    ERROR_aPH1_bSP_HSK_MISSMATCH = 421,
    ERROR_aPH1_bSP_HSK_FORBID = 431,
    ERROR_aPH_bSP_HSK_FORBID = 432,
    ERROR_aPH_bPH1_HSK_ERROR = 441,
    ERROR_aSR_bPH_HSK_ERROR = 442,
    ERROR_aLG_bS_TOKEN_NOT_FOUND = 451,
    ERROR_aLG_bPH_HSK_TIMEOUT = 452,
    ERROR_aLG_bS_TOKEN_ERROR = 453,
    ERROR_aLG_bPH_HSK_ERROR = 454,
    // ----------GUESS PROTOCOL (501-599)--------------
    ERROR_aGP_INCOMPLETE = 501,
    ERROR_aGP_GUESS = 502,
    // ----------FUNCTIONAL ERROR----------------------
    ERROR_FUNC_GENERAL = 601,
    ERROR_CLOUD_CONN_REJ = 602,
    ERROR_DEVICE_INFO = 603,
    ERROR_CLOUD_NO_DEVICE_LIST = 604,
    ERROR_ALIAS_NOT_FOUND = 605,
    ERROR_FUNC_VALID_COLOR = 651,
    ERROR_FUNC_TEMP_COLOR = 652,
    ERROR_FUNC_HEX_COLOR = 653,
    ERROR_FUNC_KEY_LENGTH = -1010,
    ERROR_FUNC_BAD_CREDENTIALS = -1501,
    ERROR_FUNC_BAD_REQUEST = -1002,
    ERROR_FUNC_BAD_JSON = -1003,
    ERROR_FUNC_WRONG_EMAIL = -20601,
    ERROR_FUNC_CLOUD_TOKEN_EXPIRED = -20675,
    ERROR_FUNC_DEV_TOKEN_EXPIRED = 9999,
    ERROR_FUNC_UNEXPECTED = 19999
}

export enum ErrorMsg {
    // ----------GENERAL ERROR (1-99)-------------------
    ERROR_AXIOS_ERROR = "Axios error: ",
    ERROR_TAPRES_JSON_INVALID = "Invalid JSON answer: ",
    ERROR_AXIOS_FORBID = "Negotiation error: ",
    GENERIC_ERROR = "General error: ",
    // ----------ENCRIPTION ERROR (101-199)-------------
    ERROR_KL_ENCRYPT_FMT = "Encryption error: ",
    ERROR_KL_ENCRYPT_IV_LENGTH = "Encryption error: ",
    ERROR_CH_UNABLE_KEYS = "Encryption error: ",
    ERROR_SNOW_WORKER_ID = "Encryption error: ",
    ERROR_SNOW_DATA_CENTER_ID = "Encryption error: ",
    ERROR_SNOW_INVALID_TIME_ID = "Encryption error: ",
    // ----------SESSION POST ERROR (201-299)-----------
    ERROR_aSP_bAX_REQ_ERR = "Device comm error: ",
    ERROR_aSP_bAX_REQ_FORBID = "Device comm rejected: ",
    ERROR_aSP_bAX_INVALID_URL = "URL not valid: ",
    // ----------SEND REQUEST ERROR (301-399)-----------
    ERROR_aSR_bSR_RET_ERR = "Instant retry error: ",
    ERROR_aSR_bSR_MAX_RET = "Max retries reached: ",
    ERROR_aSR_bSP_REQ_ERR = "Device request error: ",
    ERROR_aSR_bSP_REJ = "Device comm rejected: ",
    ERROR_aSR_DEV_FORBID = "Device comm rejected: ",
    ERROR_aSR_DEV_GENERAL = "Device comm error: ",
    // ----------HANDSHAKE ERROR (401-499)--------------
    ERROR_aPH2_bSP_HSK_ERROR = "Handshake error: ",
    ERROR_aPH1_bSP_HSK_ERROR = "Handshake error: ",
    ERROR_aPH2_bSP_HSK_REJ = "Handshare rejected: ",
    ERROR_aPH_bSP_HSK_REJ = "Handshare rejected: ",
    ERROR_aPH1_bSP_HSK_MISSMATCH = "Handshake error: ",
    ERROR_aPH1_bSP_HSK_FORBID = "Handshare rejected: ",
    ERROR_aPH_bSP_HSK_FORBID = "Handshare rejected: ",
    ERROR_aPH_bPH1_HSK_ERROR = "Handshake error: ",
    ERROR_aSR_bPH_HSK_ERROR = "Handshake error: ",
    ERROR_aLG_bS_TOKEN_NOT_FOUND = "Handshake error: ",
    ERROR_aLG_bPH_HSK_TIMEOUT = "Handshake timeout: ",
    ERROR_aLG_bS_TOKEN_ERROR = "Handshake error: ",
    ERROR_aLG_bPH_HSK_ERROR = "Handshake error: ",
    // ----------GUESS PROTOCOL (501-599)--------------
    ERROR_aGP_INCOMPLETE = "Protocol not detected: ",
    ERROR_aGP_GUESS = "Protocol not detected: ",
    // ----------FUNCTIONAL ERROR----------------------
    ERROR_FUNC_GENERAL = "General functional error: ",
    ERROR_CLOUD_CONN_REJ = "Cloud connection rejected: ",
    ERROR_DEVICE_INFO = "Device comm error: ",
    ERROR_CLOUD_NO_DEVICE_LIST = "Cloud empty list: ",
    ERROR_ALIAS_NOT_FOUND = "Alias not found: ",
    ERROR_FUNC_VALID_COLOR = "Color not valid: ",
    ERROR_FUNC_TEMP_COLOR = "Color not valid: ",
    ERROR_FUNC_HEX_COLOR = "Color not valid: ",
    ERROR_FUNC_KEY_LENGTH = "Encryption error: ",
    ERROR_FUNC_BAD_CREDENTIALS = "Bad credentials: ",
    ERROR_FUNC_BAD_REQUEST = "Device request error: ",
    ERROR_FUNC_BAD_JSON = "Invalid JSON answer: ",
    ERROR_FUNC_WRONG_EMAIL = "Bad credentials: ",
    ERROR_FUNC_CLOUD_TOKEN_EXPIRED = "Token expired: ",
    ERROR_FUNC_DEV_TOKEN_EXPIRED = "Token expired: ",
    ERROR_FUNC_UNEXPECTED = "Unexpected error: "
}

// ****************************************************
// ***  TAPO CLASSES TO DEFINE TAPO CLIENT SESSIONS ***
// ****************************************************
// Class for TapoProtocol
export enum TapoProtocolType {
    PASSTHROUGH = 1,
    KLAP = 2,
    AUTO = 3,
}

// Class for Authentication credentials
export class AuthCredential {
    public username: string;
    public password: string;

    constructor(user?: string, passwd?: string) {
        this.username = (typeof(user) == 'undefined' ? '' : user);
        this.password = (typeof(passwd) == 'undefined' ? '' : passwd);

        // Set the properties to false to avoid any change or access once created
        Object.defineProperty(this, 'username', {enumerable: false, writable: false, configurable: false});
        Object.defineProperty(this, 'password', {enumerable: false, writable: false, configurable: false});
    }
}

// Class for TapoClient - connection to every Tapo device
export class TapoClient {

    // Define parameters of the class
    private _auth_credential: AuthCredential;
    public _url: string;
    public _protocol_type: TapoProtocolType;
    public _protocol: TapoProtocol;
    public _terminal_random: boolean;
    public _debug: boolean;
    public _keep_alive: boolean;

    // Eported array of functions
    public actions:  {[any: string]: (any) => any };      
    

    // Constructor to initialize the class
    constructor(auth_credential: AuthCredential, url: string, protocol?: TapoProtocolType, terminal_random?: boolean, keep_alive?: boolean, debug?: boolean) {
        this._auth_credential = auth_credential;
        let myURL = new URL("http:\\example.com");
        try {
            const myURL2 = new URL(url);
            myURL = myURL2;
        } catch (e) {
            myURL.protocol = 'http';
            myURL.hostname = url;
            myURL.port = '80';
            myURL.pathname = "/app";
        }
        this._url = myURL.href;
        this._protocol_type = (typeof(protocol) === undefined ? TapoProtocolType.AUTO : protocol);
        this._protocol = null;
        this._terminal_random = ((typeof(terminal_random) == 'undefined') ? false : terminal_random);
        this._debug = (typeof(debug) == 'undefined' ? false : debug);
        this._keep_alive = (typeof(keep_alive) == 'undefined' ? true : keep_alive);

        // Create the list of functions
        this.actions = {'list_methods': () => { return this.list_methods()},
                        'perform_handshake': (protocol?: TapoProtocolType) => { return this.perform_handshake(protocol)},
                        'get_component_negotiation': (protocol?: TapoProtocolType) => {return this.get_component_negotiation(protocol)}, 
                        'get_device_info': (protocol?: TapoProtocolType) => {return this.get_device_info(protocol)}, 
                        'get_current_power': (protocol?: TapoProtocolType) => {return this.get_current_power(protocol)},
                        'get_energy_usage': (protocol?: TapoProtocolType) => {return this.get_energy_usage(protocol)},
                        'get_child_device_list': (params?: number, protocol?: TapoProtocolType) => {return this.get_child_device_list(params, protocol)},
                        'execute_raw_request': (request: TapoRequest, protocol?: TapoProtocolType, retry?: number) => { return this.execute_raw_request(request, protocol, retry)}, 
                        'send_request': (request: TapoRequest, protocol?: TapoProtocolType) => { return this.send_request(request, protocol)},
                        'set_device_info': (params: Json_T, protocol?: TapoProtocolType) => { return this.set_device_info(params, protocol)},
                        'turn_onoff_device': (params: boolean, protocol?: TapoProtocolType) => { return this.turn_onoff_device(params, protocol)},
                        'set_color_device': (params: string, protocol?: TapoProtocolType) => { return this.set_color_device(params, protocol)},
                        'set_brightness_device': (params: number, protocol?: TapoProtocolType) => { return this.set_brightness_device(params, protocol)}};

        // Set the properties to false to avoid any change or access once created
        if (!this._debug) {
            Object.defineProperty(this, '_auth_credential', {enumerable: false});
            Object.defineProperty(this, '_protocol', {enumerable: false});
            Object.defineProperty(this, '_protocol_type', {enumerable: false});
            Object.defineProperty(this, '_terminal_random', {enumerable: false});
            Object.defineProperty(this, '_debug', {enumerable: false});
            Object.defineProperty(this, '_keep_alive', {enumerable: false});
        }
    }

    // Private methods to setup the protocol
    private async _initialize_protocol_if_needed(protocol?: TapoProtocolType): Promise<void> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        if ((this._protocol == null) || ((this._protocol._protocol_type != proto) && (proto != TapoProtocolType.AUTO))) this._protocol = await this._guess_protocol(proto);
    }

    private async _guess_protocol(protocol?: TapoProtocolType): Promise<TapoProtocol> {

        // Process parameters
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);

        // Process the ptotocol if it is not AUTO
        if (proto == TapoProtocolType.PASSTHROUGH) {
            
            // Try PASSTHROUGH protocol
            try {

                // Set PASSTHROGH and get the components
                if (this._debug) console.debug("Set protocol to PASSTHROUGH");
                this._protocol = new PassthroughProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                const resp: Components = await this.get_component_negotiation(proto, MAX_RETRIES_GUESS);

            } catch (error: any) {
                
                // Close this protocol and try again without keep_alive
                this.close();
                this._keep_alive = false;
                try {

                    // Set PASSTHROGH and get the components
                    if (this._debug) console.debug("Set protocol to PASSTHROUGH - Keep alive forced to false");
                    this._protocol = new PassthroughProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                    const resp: Components = await this.get_component_negotiation(proto, MAX_RETRIES_GUESS);
    
                } catch (error: any) {
                    this.close();
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aGP_INCOMPLETE]] + 'Negotiation not completed', error, ErrorCode.ERROR_aGP_INCOMPLETE, this._guess_protocol.name);
                }
            }

            // Return the final protocol
            return this._protocol;

        } else if (proto == TapoProtocolType.KLAP) {
            
            // Try KLAP protocol
            try {

                // Set KLAP and get the components
                if (this._debug) console.debug("Set protocol to KLAP");
                this._protocol = new KlapProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                const resp: Components = await this.get_component_negotiation(proto, MAX_RETRIES_GUESS);

            } catch (error: any) {
                                
                // Close this protocol and try again without keep_alive
                this.close();
                this._keep_alive = false;
                try {

                    // Set KLAP and get the components
                    if (this._debug) console.debug("Set protocol to KLAP - Keep alive forced to false");
                    this._protocol = new KlapProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                    const resp: Components = await this.get_component_negotiation(proto, MAX_RETRIES_GUESS);
    
                } catch (error: any) {
                    this.close();
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aGP_INCOMPLETE]] + 'Negotiation not completed', error, ErrorCode.ERROR_aGP_INCOMPLETE, this._guess_protocol.name);
                }
            }
            
            // Return the final protocol
            return this._protocol;

        } else {
        
            // Try first with PassthroughProtocol
            const ka_bck: boolean = this._keep_alive;
            try {

                // Set Passthrough and get the components
                if (this._debug) console.debug("Trying first with PassthroughProtocol");
                this._protocol = new PassthroughProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                const resp: Components = await this.get_component_negotiation(TapoProtocolType.PASSTHROUGH, MAX_RETRIES_GUESS)

            } catch (error: any) {

                // Close this protocol and try again without keep_alive
                this.close();
                this._keep_alive = false;
                try {

                    // Set Passthrough without keep_alive and get the components
                    if (this._debug) console.debug("Trying again with PassthroughProtocol - Keep alive forced to false");
                    this._protocol = new PassthroughProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                    const resp: Components = await this.get_component_negotiation(proto, MAX_RETRIES_GUESS);

                } catch (error: any) {
                                
                    // Try to fallback to KLAP
                    this.close();
                    this._keep_alive = ka_bck;
                    try {

                        // Set KLAP and get the components
                        if (this._debug) console.debug("Default protocol not working. Fallback to KLAP");
                        this._protocol = new KlapProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                        const resp_klap: Components = await this.get_component_negotiation(TapoProtocolType.KLAP, MAX_RETRIES_GUESS);

                    } catch (error: any) {
                        
                        // Set KLAP and try again without keep_alive
                        this.close();
                        this._keep_alive = false;
                        try {

                            // Set KLAP and get the components
                            if (this._debug) console.debug("Default protocol not working. Fallback to KLAP - Keep alive forced to false");
                            this._protocol = new KlapProtocol(this._auth_credential, this._url, this._terminal_random, this._keep_alive, this._debug);
                            const resp: Components = await this.get_component_negotiation(proto, MAX_RETRIES_GUESS);
            
                        } catch (error: any) {
                            this.close();
                            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aGP_INCOMPLETE]] + 'Negotiation not completed', error, ErrorCode.ERROR_aGP_INCOMPLETE, this._guess_protocol.name);
                        }
                    }
                }
            };

            // Return the final protocol
            return this._protocol;
        }
    }

    // Public protocol exposed methods for external control
    public async perform_handshake(protocol?: TapoProtocolType): Promise<TapoClient> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        await this._initialize_protocol_if_needed(proto);
        this._protocol._session = await this._protocol.perform_handshake();
        return this;
    }

    // Public method to expose protocol send request
    public async send_request(request: TapoRequest, protocol?: TapoProtocolType): Promise<TapoResponse<Json_T>> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        await this._initialize_protocol_if_needed(proto);
        if ((this._protocol._session == null) || (!this._protocol._session.handshake_complete) || (this._protocol._session.is_handshake_session_expired())) {
            this._protocol._session = await this._protocol.perform_handshake();
        }
        return this._protocol.send_request(request);
    }

    // Public method to close the session
    public close(): void {
        if (this._protocol != null) this._protocol.close(false);
    }

    // Public methods to execute raw request
    public async execute_raw_request(request: TapoRequest, protocol?: TapoProtocolType, retry?: number): Promise<Json_T> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        await this._initialize_protocol_if_needed(proto);
        return await this._protocol.send_request(request, ((typeof(retry) == 'undefined') ? undefined : retry))
            .then ((value: TapoResponse<Json_T>): Json_T => {
                return value.result;
            });
    }

    // Public methods to execute different kind of requests
    public async get_component_negotiation(protocol?: TapoProtocolType, retry?: number): Promise<Components> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return new Components().try_from_json(await this.execute_raw_request(new TapoRequest().component_negotiation(), proto, retry))
    }
    public async get_device_info(protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().get_device_info(), proto);
    }
    public async get_current_power(protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().get_current_power(), proto);
    }
    public async get_energy_usage(protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().get_energy_usage(), proto);
    }
    public async set_device_info(params: Json_T, protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().set_device_info(params), proto);
    }
    public async turn_onoff_device(params?: boolean, protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().turn_onoff_device((typeof(params) == 'undefined') ? false : params), proto);
    }
    public async set_color_device(params?: string, protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().set_color_device((typeof(params) == 'undefined') ? "white" : params), proto);
    }
    public async set_brightness_device(params?: number, protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().set_brightness_device((typeof(params) == 'undefined') ? 100 : params), proto);
    }
    public async get_child_device_list(params?: number, protocol?: TapoProtocolType): Promise<Json_T>{
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?this._protocol_type:protocol);
        return await this.execute_raw_request(new TapoRequest().get_child_device_list((typeof(params) == 'undefined') ? 0 : params), proto);
    }
    public list_methods(): any {
        return Object.keys(this.actions);
    }
}

// Class for different TapoRequests
export class TapoRequest {

    // Parameters defining the request
    public method: string;
    public params: object;
    public requestID: number;
    public request_time_millis: number;
    public terminal_uuid: string;

    // Constructor to initialize the class
    constructor(method?: string, params?: object) {
        this.method = (typeof(method) == 'undefined' ? undefined : method);
        this.params = (typeof(params) == 'undefined' ? undefined : params);
    }

    // Define the different methods
    public handshake(params: HandshakeParams): TapoRequest {
        this.method = "handshake";
        this.params = params;
        return this;
    }
    public login(credential: AuthCredential, v2?: boolean): TapoRequest {
        this.method = "login_device";
        this.params = (((typeof(v2) == 'undefined') || (!v2)) ? new LoginDeviceParams(credential.username, credential.password) : new LoginDeviceParamsV2(credential.username, credential.password));
        return this;
    }
    public cloud_login(credential: AuthCredential): TapoRequest {
        this.method = "login";
        this.params = {"appType": "Tapo_Android", "cloudPassword": credential.password, "cloudUserName": credential.username, "terminalUUID": uuidv4()}
        return this;
    }
    public cloud_list_devices(): TapoRequest {
        this.method = "getDeviceList";
        this.params = undefined;
        return this;
    }
    public secure_passthrough(params: SecurePassthroughParams) : TapoRequest {
        this.method = "securePassthrough";
        this.params = params;
        return this;
    }
    public get_device_info() : TapoRequest {
        this.method = "get_device_info";
        this.params = undefined;
        return this;
    }
    public get_device_usage() : TapoRequest {
        this.method = "get_device_usage";
        this.params = undefined;
        return this;
    }
    public get_energy_usage() : TapoRequest {
        this.method = "get_energy_usage";
        this.params = undefined;
        return this;
    }
    public set_device_info(params: Json_T) : TapoRequest {
        this.method = "set_device_info";
        this.params = params;
        return this;
    }
    public turn_onoff_device(params: boolean) : TapoRequest {
        this.method = "set_device_info";
        this.params = {"device_on": params};
        return this;
    }
    public set_color_device(params: string) : TapoRequest {
        this.method = "set_device_info";
        this.params = new ColorParams().get_color(params);
        return this;
    }
    public set_brightness_device(params: number) : TapoRequest {
        this.method = "set_device_info";
        this.params = {"brightness": Math.max(0, Math.min(params, 100))}
        return this;
    }
    public get_current_power() : TapoRequest {
        this.method = "get_current_power";
        this.params = undefined;
        return this;
    }
 //   public set_lighting_effect(effect: LightEffect) : TapoRequest {
 //       return new TapoRequest("set_lighting_effect", effect);
 //   }
    public get_child_device_list(start_index: number) : TapoRequest {
        this.method = "get_child_device_list";
        this.params = new PaginationParams(start_index);
        return this;
    }
    public get_child_device_component_list() : TapoRequest {
        this.method = "get_child_device_component_list";
        this.params = undefined;
        return this;
    }
    public multiple_request(requests: MultipleRequestParams) : TapoRequest {
        this.method = "multipleRequest";
        this.params = undefined;
        return this;
    }
    public control_child(device_id: string, request: TapoRequest) : TapoRequest {
        this.method = "control_child";
        this.params = new ControlChildParams(device_id, request);
        return this;
    }
 //   public get_child_event_logs(trigger_log_params: GetTriggerLogsParams) : TapoRequest {
 //       return new TapoRequest("get_trigger_logs", trigger_log_params);
 //   }
    public get_temperature_humidity_records() : TapoRequest {
        this.method = "get_temp_humidity_records";
        this.params = undefined;
        return this;
    }
    public component_negotiation() : TapoRequest {
        this.method = "component_nego";
        this.params = undefined;
        return this;
    }
    public with_request_id(request_id: number) : TapoRequest {
        this.requestID = request_id;
        return this;
    }
    public with_request_time_millis(t: number) : TapoRequest {
        this.request_time_millis = t;
        return this;
    }
    public with_terminal_uuid(uuid: string) : TapoRequest {
        this.terminal_uuid = uuid;
        return this;
    }
    public get_params() : object {
        return this.params;
    }
    public get_method() : string {
        return this.method;
    }
    public __eq__(other: TapoRequest): boolean {
        if (!(other instanceof TapoRequest)) {
            return false;
        } else {
            return ((this.method === other.method) && (this.params === other.params));
        }
    }
}

// Class for different TapoResponses
export class TapoResponse<Json_T> {
    
    // Define parameters of the class
    error_code: number;
    result: any;
    msg?: string;

    // Constructor of the class
    constructor(err?: number, res?: any, mg?: string) {
        this.error_code = (typeof(err) == 'undefined' ? 0 : err);
        this.result = (typeof(res) == 'undefined' ? null: res);
        this.msg = (typeof(mg) == 'undefined' ? '' : mg);
    }

    // Methods defined in the class
    public async try_from_json(json: Json_T): Promise<TapoResponse<Json_T>> {

        // Process the response from server to get the three fields
        this.error_code = (typeof(json["error_code"]) == 'undefined' ? 0 : json["error_code"]);
        this.result = (typeof(json["result"]) == 'undefined' ? null : json["result"]);
        this.msg = (typeof(json["msg"]) == 'undefined' ? 'No message' : json["msg"]);

        // Return this same class instance
        await this.check_Error();
        return this;
    }

    // Private method to check functional errors
    public async check_Error() {
            
        // Throw an error in case it is different from 0
        switch (this.error_code) {
            case 0:         break;
            case -1010:     throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_KEY_LENGTH]] + "Invalid public key length", null, ErrorCode.ERROR_FUNC_KEY_LENGTH, this.check_Error.name);
            case -1501:     throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_BAD_CREDENTIALS]] + "Invalid request or credentials", null, ErrorCode.ERROR_FUNC_BAD_CREDENTIALS, this.check_Error.name);
            case -1001:     throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_BAD_REQUEST]] + "Incorrect request", null, ErrorCode.ERROR_FUNC_BAD_REQUEST, this.check_Error.name);
            case -1002:     throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_BAD_REQUEST]] + "Incorrect request", null, ErrorCode.ERROR_FUNC_BAD_REQUEST, this.check_Error.name);
            case -1003:     throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_BAD_JSON]] + "JSON format error", null, ErrorCode.ERROR_FUNC_BAD_JSON, this.check_Error.name);
            case -20601:    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_WRONG_EMAIL]] + "Incorrect email or password", null, ErrorCode.ERROR_FUNC_WRONG_EMAIL, this.check_Error.name);
            case -20675:    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_CLOUD_TOKEN_EXPIRED]] + "Cloud token expired or invalid", null, ErrorCode.ERROR_FUNC_CLOUD_TOKEN_EXPIRED, this.check_Error.name);
            case 9999:      throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_DEV_TOKEN_EXPIRED]] + "Device token expired or invalid", null, ErrorCode.ERROR_FUNC_DEV_TOKEN_EXPIRED, this.check_Error.name);
            default:        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_UNEXPECTED]] + `Unexpected Error Code: ${this.error_code} (${this.msg})`, null, ErrorCode.ERROR_FUNC_UNEXPECTED, this.check_Error.name);
        }
    }
}

// Class for different Request parameters
export class HandshakeParams {

    // Define parameters of the class
    public key: object;

    //Constructor to initialize the class
    constructor(key: object) {
        this.key = key;
    }
}
export class LoginDeviceParams {

    // Define parameters of the class
    password: string;
    username: string;

    // Constructor to initialize the class
    constructor(user: string, pass: string) {
        this.username = Buffer.from(createHash("sha1").update(user).digest('hex')).toString('base64');
        this.password = Buffer.from(pass).toString('base64');
    }
}
export class LoginDeviceParamsV2 {

    // Define parameters of the class
    password2: string;
    username: string;

    // Constructor to initialize the class
    constructor(user: string, pass: string) {
        this.username = Buffer.from(createHash("sha1").update(user).digest('hex')).toString('base64');
        this.password2 = Buffer.from(createHash("sha1").update(pass).digest('hex')).toString('base64');
    }
}
export class SecurePassthroughParams {

    // Define parameters of the class
    public request: string;

    // Constructor
    constructor(request: string) {
        this.request = request;
    }
}
export class PaginationParams {

    // Define parameters of the class
    public start_index: number;

    // Constructor to initialize the class
    constructor(idx: number) {
        this.start_index = idx;
    }
}
export class MultipleRequestParams {

    // Define parameters of the class
    requests: TapoRequest[];
}
export class ControlChildParams {

    // Define parameters of the class
    public device_id: string;
    public requestData: TapoRequest;

    // Constructor to initialize the class
    constructor(device: string, request: TapoRequest) {
        this.device_id = device;
        this.requestData = request;
    }
}
export class Components {

    // Define parameters of the class
    public component_list: Json_T;

    // Constructor of the class
    constructor(list?: Json_T){
        this.component_list = list;
    }

    // Methods of the class
    public try_from_json(data: Json_T): Components {
        const components = data["component_list"] || [];
        this.component_list = components.reduce((acc: { [key: string]: string }, c: { [key: string]: string }) => {
            acc[c["id"]] = c["ver_code"];
            return acc;
        }, {});
        return this;
    }
}
export class ColorParams {

    // Define constants for preset colors
    public preset = {
        blue: {
            hue: 240,
            saturation: 100,
            color_temp: 0
            },
        red: {
            hue: 0,
            saturation: 100,
            color_temp: 0
            },
        yellow: {
            hue: 60,
            saturation: 100,
            color_temp: 0
            },
        green: {
            hue: 120,
            saturation: 100,
            color_temp: 0
            },
        white: {
            color_temp: 4500
            },
        daylightwhite: {
            color_temp: 5500
            },
        warmwhite: {
            color_temp: 2700
            }
    }
  
    private HEXtoHSL(hex: string) {

        // Check valid hex color
        if (hex.toLowerCase() === '#000000') throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_HEX_COLOR]] + 'Cannot set light to black', null, ErrorCode.ERROR_FUNC_HEX_COLOR, this.HEXtoHSL.name);
        let result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    
        // Return i fnull color
        if( result == null ) return;
    
        // Get RGB components
        let r = parseInt(result[1], 16);
        let g = parseInt(result[2], 16);
        let b = parseInt(result[3], 16);  
        r /= 255, g /= 255, b /= 255;
    
        // Get Hue, Saturation and Brightness components
        let max = Math.max(r, g, b), min = Math.min(r, g, b);
        let h = 0, s = 0, l = (max + min) / 2;
        if(max == min){
            h = s = 0; // achromatic
        } else {
            let d = max - min;
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            switch(max) {
                case r: h = (g - b) / d + (g < b ? 6 : 0); break;
                case g: h = (b - r) / d + 2; break;
                case b: h = (r - g) / d + 4; break;
            }
            h /= 6;
        }
        s = s * 100;
        s = Math.round(s);
        l = l * 100;
        l = Math.round(l);
        h = Math.round(360 * h);
    
        // Return hue, saturation and brightness
        return { hue: h, saturation: s, brightness: l };
    }
  
    private temperature(temp: string): Json_T {
        
        let t = parseInt(temp.slice(0,-1));
        if (t<2500||t>6500) throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_TEMP_COLOR]] + 'Colour temperature should be between 2500K and 6500K.', null, ErrorCode.ERROR_FUNC_TEMP_COLOR, this.temperature.name);
        return{ color_temp: t };
    }
  
    public get_color(color: string): Json_T {
        color = color.toLowerCase();
        if (color.startsWith('#')) return this.HEXtoHSL(color);
        if (color.endsWith('k')) return this.temperature(color);
        if (Object.keys(this.preset).includes(color)) return this.preset[color] || "";
        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_VALID_COLOR]] + 'Invalid Color', null, ErrorCode.ERROR_FUNC_VALID_COLOR, this.get_color.name);
    }
}

// *********************************************
// ***  TAPO CLASSES TO DEFINE TAPO PROTOCOL ***
// *********************************************
// Class for abstract TapoProtocol
export abstract class TapoProtocol {
    public abstract _base_url: string;
    public abstract _host: string;
    public abstract _auth_credential: AuthCredential;
    public abstract _http_session: AxiosInstance;
    public abstract _http_agent: http.Agent | https.Agent;
    public abstract _session: TapoSession;  
    public abstract _jar: Json_T;
    public abstract _protocol_type: TapoProtocolType;
    public abstract _terminal_random: boolean;
    public abstract perform_handshake();
    public abstract send_request(request: TapoRequest, retry?: number):Promise<TapoResponse<any>>;
    public abstract close(change_agent?: boolean): void;
}

// Class for abstract TapoSession
export abstract class TapoSession {
    public abstract chiper: TapoChiper;
    public abstract session_id: string;
    public abstract expire_at: number;
    public abstract handshake_complete: boolean;
    public abstract terminal_uuid: string;
    public abstract get_cookies(): [Json_T, string];
    public abstract is_handshake_session_expired():boolean;
    public abstract invalidate(): void;
    public abstract complete_handshake(chiper: TapoChiper):TapoSession;
}

// Class for abstract TapoChiper
export abstract class TapoChiper {
    public abstract _key: Buffer;  // Key - Algorithm of bytes (128 bits)
    public abstract _iv: Buffer;   // Initialization vector - First 12 bytes of sha256
}

// Class to manage TapoErrors
export class TapoError {

    //Define the parameters of the class
    public error_code: number;
    public message: string;
    public agent: string;
    public cause?: Cause;
    public track?: TapoError;

    // Constructor of the class
    constructor (message?: string, track?: TapoError, code?: number, agent?: string) {
        
        // Define first the non-recursive properties
        this.error_code = (typeof(code) == 'undefined') ? ErrorCode.GENERIC_ERROR : code;
        this.message = (typeof(message) == 'undefined' ? '' : message);
        this.agent = agent;

        // Define the recursive ones taking care of the non-recursive already defined and availability ot track and track.cause
        this.track = ((typeof(track) == 'undefined') || (track == null)) ? undefined : track;
        if ((typeof(track) == 'undefined') || (track == null) || (!(track instanceof TapoError))) {
            this.cause = {error_code: this.error_code, message: this.message, agent: this.agent}
        } else if ((typeof(track.cause) == 'undefined') || (track.cause == null)) {
            this.cause = track.get_current_cause()
        } else {
            this.cause = track.cause
        }

        // Delete the empty objects on track and cause
        if ((typeof(this.track) != 'undefined') && (track != null)) {
            delete this.track.cause
        } else {
            delete this.track
        }
    }

    //Public method to transfer Axios to Tapo
    public axios_to_tapo(axios: AxiosError): TapoError {
        if (axios.code == "ERR_BAD_REQUEST") {
            this.error_code = ErrorCode.ERROR_AXIOS_FORBID;
        } else {
            this.error_code = ErrorCode.ERROR_AXIOS_ERROR;
        }
        this.message = ErrorMsg[ErrorCode[this.error_code]] + axios.code + ' - ' + axios.message;
        this.agent = axios.name;
        this.cause = {message: this.message, error_code: this.error_code, agent: this.agent};
        return this;
    }

    // Public method to get the Cause
    public get_current_cause(): Cause {
        return {error_code: this.error_code, message: this.message, agent: this.agent}
    }
}

// *********************************************
// ***  KLAP CLASSES TO DEFINE KLAP PROTOCOL ***
// *********************************************
// Class for Klap Protocol definition
export class KlapProtocol extends TapoProtocol {

    // Parameters defining the Tapo Klap Protocol
    public _base_url: string;
    public _host: string;
    public _auth_credential: AuthCredential;
    public _local_seed: Buffer | null;
    public local_auth_hash: Buffer;
    public _jar: Json_T;
    public _http_session: AxiosInstance;
    public _http_agent: http.Agent | https.Agent;
    public _session: KlapSession | null;
    public _request_id_generator: SnowflakeId;
    public _protocol_type: TapoProtocolType;
    public _terminal_random: boolean;
    public _keep_alive: boolean;
    public _debug: boolean;

     // Constructor to initialize the class
    constructor(auth_credential: AuthCredential, url: string, terminal_random?: boolean, keep_alive?: boolean, debug?: boolean) {
        super();
        this._base_url = url;
        this._host = (new URL(this._base_url)).hostname;
        this._auth_credential = auth_credential;
        this.local_auth_hash = this.generate_auth_hash(this._auth_credential);
        this._local_seed = null;
        this._jar = null;
        this._session = null;
        this._protocol_type = TapoProtocolType.KLAP;
        this._terminal_random = ((typeof(terminal_random) == 'undefined') ? false : terminal_random);
        this._request_id_generator = new SnowflakeId(1, 1);
        this._keep_alive = ((typeof(keep_alive) == 'undefined') ? true : keep_alive);
        this._debug = (typeof(debug) == 'undefined' ? false : debug);
        try {
            this._http_agent = (new URL(url).protocol == 'https:' ? new https.Agent({ keepAlive: true, timeout: AXIOS_TIMEOUT }) : new http.Agent({ keepAlive: true, timeout: AXIOS_TIMEOUT }));
            this._http_session = axios.create({timeout: AXIOS_TIMEOUT, httpAgent: this._http_agent, validateStatus: () => {return true}, proxy: false});
        } catch (err) {
            new TapoError(ErrorMsg[ErrorCode[ErrorCode.GENERIC_ERROR]] + 'Agent error - ' + err, null, ErrorCode.GENERIC_ERROR, this.constructor.name)
        }

        // Set the properties to false to avoid any change or access once created
        if (!this._debug) {
            Object.defineProperty(this, '_auth_credential', {enumerable: false});
            Object.defineProperty(this, '_http_session', {enumerable: false});
            Object.defineProperty(this, '_http_agent', {enumerable: false});
            Object.defineProperty(this, '_session', {enumerable: false});
            Object.defineProperty(this, '_jar', {enumerable: false});
            Object.defineProperty(this, 'local_auth_hash', {enumerable: false});
            Object.defineProperty(this, '_local_seed', {enumerable: false});
            Object.defineProperty(this, '_keep_alive', {enumerable: false});
            Object.defineProperty(this, '_debug', {enumerable: false});
        }
    }
 
    // Private method to generate Authentication hash
    public generate_auth_hash(auth: AuthCredential): Buffer {
        return this._sha256(Buffer.concat([
            this._sha1(Buffer.from(new TextEncoder().encode(auth.username))), 
            this._sha1(Buffer.from(new TextEncoder().encode(auth.password)))
        ]));
    }

    public _sha1(payload: Buffer): Buffer {
        return createHash("sha1").update(payload).digest();
    }

    public _sha256(payload: Buffer): Buffer {
        return createHash("sha256").update(payload).digest();
    }

    // Private method to post a session
    public async session_post(url: string, data: any, cookies?: any, params?: any): Promise<[AxiosResponse, Buffer]> {
        this._jar = null;
        const config: AxiosRequestConfig = {url: url, method: 'post', data: data, headers: (typeof(cookies) == 'undefined'?undefined:{'Cookie': cookies}), params: (typeof(params) == 'undefined'?undefined:params), responseType: 'arraybuffer'};
        const response: AxiosResponse = await this._http_session.request(config)
            .then((value: AxiosResponse): AxiosResponse => {  
                
                // Check status of the answer
                if (value.status != 200) {
                    this._http_agent.destroy();
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSP_bAX_REQ_FORBID]] + 'URL error - ' + value.statusText + " - " + value.status, null, ErrorCode.ERROR_aSP_bAX_REQ_FORBID, this.session_post.name)
                } else {

                    // Get the cookies
                    if (value.headers.hasOwnProperty('set-cookie')) {
                            const cookies = value.headers['set-cookie'][0].split(';');
                            for (let i=0; i < cookies.length; i++ ) {
                                if (cookies[i].includes('=')) {
                                    this._jar = {...this._jar, [cookies[i].split('=')[0]]: cookies[i].split('=')[1]}
                                }    
                            }
                    }
                                        
                    // Return value
                    return value;
                }
            })
            .catch((error: AxiosError) => {
                this._http_agent.destroy();
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSP_bAX_REQ_ERR]] + 'Session_post error - Axios', new TapoError().axios_to_tapo(error), ErrorCode.ERROR_aSP_bAX_REQ_ERR, this.session_post.name)
            });
        
        // Build and return the array of response
        const empty: string = JSON.stringify({});
        return [response, (((response.data != null) && (typeof(response.data) != 'undefined')) ? Buffer.from(response.data): Buffer.from(empty))];
    }
   
    // Private method Handshake to perform the full Handshake and get a valid KlapSession
    public async perform_handshake(new_local_seed?: Buffer): Promise<KlapSession> {
        if (this._debug) console.debug("[KLAP] Starting handshake with " + this._host);
        const seeds: KlapSession = await this.perform_handshake1((typeof(new_local_seed) == 'undefined' ? undefined : new_local_seed))
            .then (async (value: [Buffer, Buffer]) => {
                const [remote_seed, auth_hash]: [Buffer, Buffer] = value;
                const session: KlapSession = await this.perform_handshake2(this._local_seed, remote_seed, auth_hash)
                    .then((value: KlapSession) => {
                        if (this._debug) console.debug("[KLAP] Handshake with " + this._host + " complete");
                        return value;
                    });
                return session;
            })
            .catch ((error: TapoError) => {
                this.close(false);
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH_bPH1_HSK_ERROR]] + "Handshake error - " + error.message, error, ErrorCode.ERROR_aPH_bPH1_HSK_ERROR, this.perform_handshake.name)
            });
        return seeds;
    }

    // Private method Handshake1 to get remote_seed and auth_hash
    public async perform_handshake1(new_local_seed?: Buffer): Promise<[Buffer, Buffer]> {
        
        // Set local seed as random 16 bytes seed if not provided
        this._local_seed = (typeof(new_local_seed) == 'undefined' ? Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))) : new_local_seed);

        // Prepare post parameters
        this._session = null;
        const url: string = this._base_url + "/handshake1";

        // Send the request and check if servers answers with HTTP200
        const seeds: [Buffer, Buffer] = await this.session_post(url, this._local_seed)
            .then((value: [AxiosResponse, Buffer]): [Buffer, Buffer] => {
                if (value[0].status != 200) {
                    this._http_agent.destroy();
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH1_bSP_HSK_FORBID]] + "Device failed to respond to handshake1 with " + value[0].status, null, ErrorCode.ERROR_aPH1_bSP_HSK_FORBID, this.perform_handshake1.name)
                } else {
                    
                    // Define a new KlapSession object for the session and retrieve parameters - Session_id, Timeout, remote_seed and server_hash
                    const terminal_uuid = (this._terminal_random ? webcrypto.randomUUID() : uuidv4());
                    this._session = new KlapSession(this._jar[TP_SESSION_COOKIE_NAME], parseInt(this._jar["TIMEOUT"],10), false, terminal_uuid);
                    const remote_seed: Buffer = value[1].subarray(0,16);
                    const server_hash: Buffer = value[1].subarray(16); 

                    // Information for debugging
                    if (this._debug) console.debug("Handshake1 posted " + new Date().getTime() + ". Host is " + this._host + ", Session cookie is " + this._session.session_id + ", Response status is " + value[0].status + ", Request was " + this.local_auth_hash.toString('hex'));
                    if (this._debug) console.debug("Server remote_seed is " + remote_seed.toString('hex') + ", server hash is " + server_hash.toString('hex'));

                    // Build the local seed auth hash
                    const local_seed_auth_hash: Buffer = this._sha256(Buffer.from(new Uint8Array([...this._local_seed, ...remote_seed, ...this.local_auth_hash])));

                    // Check the locally generated hash with the server one
                    if (Buffer.compare(local_seed_auth_hash, server_hash) == 0) {
                        if (this._debug) console.debug("Handshake1 hashes matched")
                        return [remote_seed, this.local_auth_hash];
                    } else {

                        // Check blank auth 
                        if (this._debug) console.debug("Expected " + local_seed_auth_hash.toString('hex') + " got " + server_hash.toString('hex') + " in handshake1. Checking if blank auth is a match");
                        const blank_auth: AuthCredential = new AuthCredential();
                        const blank_auth_hash: Buffer = this.generate_auth_hash(blank_auth);
                        const blank_seed_auth_hash: Buffer = this._sha256(Buffer.from(new Uint8Array([...this._local_seed, ...remote_seed, ...blank_auth_hash])));
                        if (Buffer.compare(blank_seed_auth_hash, server_hash) == 0) {
                            if (this._debug) console.debug("Server response doesn't match our expected hash on ip " + this._host + " but an authentication with blank credentials matched");
                            return [remote_seed, blank_auth_hash];
                        } else {

                            // Check kasa setup auth
                            const kasa_setup_auth: AuthCredential = new AuthCredential(TP_TEST_USER, TP_TEST_PASSWORD);
                            const kasa_setup_auth_hash: Buffer = this.generate_auth_hash(kasa_setup_auth);
                            const kasa_setup_seed_auth_hash: Buffer = this._sha256(Buffer.from(new Uint8Array([...this._local_seed, ...remote_seed, ...kasa_setup_auth_hash])));
                            if (Buffer.compare(kasa_setup_seed_auth_hash, server_hash) == 0) {
                                this.local_auth_hash = kasa_setup_auth_hash;
                                if (this._debug) console.debug("Server response doesn't match our expected hash on ip " + this._host + " but an authentication with kasa setup credentials matched");
                                return [remote_seed, kasa_setup_auth_hash];
                            } else {
                                this._session = null;
                                if (this._debug) console.debug("Server response doesn't match our challenge on ip " + this._host);
                                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH1_bSP_HSK_MISSMATCH]] + "Server response doesn't match our challenge on ip " + this._host, null, ErrorCode.ERROR_aPH1_bSP_HSK_MISSMATCH, this.perform_handshake1.name)
                            }
                        }
                    }
                }
            })
            .catch((error: TapoError) => {
                this._http_agent.destroy();
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH1_bSP_HSK_ERROR]] + "Handshake1 error - " + error.message, error, ErrorCode.ERROR_aPH1_bSP_HSK_ERROR, this.perform_handshake1.name)
            });
        return seeds;
    }

    // Private method Handshake2 to get a valid KlapSession
    public async perform_handshake2(local_seed: Buffer, remote_seed: Buffer, auth_hash: Buffer): Promise<KlapSession> {

        // Prepare post parameters - Handshake2 uses the remote seed, local seed and auth hash to check answer from server
        const url: string = this._base_url + "/handshake2";
        const payload: Buffer = this._sha256(Buffer.from(new Uint8Array([...remote_seed, ...local_seed, ...auth_hash])));
       
       // Send the request and check if server answers with HTTP 200
        const response: KlapSession = await this.session_post(url, payload, this._session.get_cookies()[1])
            .then((value: [AxiosResponse, Buffer]): KlapSession => {
                if (this._debug) console.debug("Handshake2 posted " + new Date().getTime() + ". Host is " + this._host + ", Response status is " + value[0].status + ", Request was " + payload.toString());
                if (value[0].status != 200) {
                    this.close(false);
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH2_bSP_HSK_REJ]] + "Device responded with " + value[0].status + " to handshake2", null, ErrorCode.ERROR_aPH2_bSP_HSK_REJ, this.perform_handshake2.name)
                } else {
                    const chiper: KlapChiper = new KlapChiper(local_seed, remote_seed, auth_hash);
                    return this._session.complete_handshake(chiper);
                }
            })
            .catch((error: TapoError) => {
                this.close(false);
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH2_bSP_HSK_ERROR]] + "Device responded with " + error.message + " to handshake2", error, ErrorCode.ERROR_aPH2_bSP_HSK_ERROR, this.perform_handshake2.name)
            });
        return response;
    }

    // Public method to send a request with 3 retries
    public async send_request( request: TapoRequest, retry?: number): Promise<TapoResponse<Json_T>> {
        const retr = (typeof(retry) == 'undefined' ? 3 : retry);
		const response: TapoResponse<Json_T> = await this._send_request(request, retr)
            .then((value: TapoResponse<Json_T>) => { return value })
            .catch(async (error: TapoError) => {
                if (retr > 0) {
                    try {
                        return await this.send_request(request, retr - 1);
                    } catch (error) {
                        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bSR_RET_ERR]] + "Send request failed - Retry nº " + retr.toString(), error, ErrorCode.ERROR_aSR_bSR_RET_ERR, this.send_request.name);
                    }
                } else {
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bSR_MAX_RET]] + "Send request max retries failed", error, ErrorCode.ERROR_aSR_bSR_MAX_RET, this.send_request.name)
                }
            });
        return response; 
	}

    // Public method to send every request
    public async _send_request( request: TapoRequest, retry?: number): Promise<TapoResponse<Json_T>> {
	    
        // Check if there is an existing valid session - create one if it does not
        if ((this._session == null) || !(this._session.handshake_complete)) {
			const new_session = await this.perform_handshake()
                .then ((value: KlapSession) => {
                    this._session = value;
                    return value;
                })
                .catch((error: TapoError) => {
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bPH_HSK_ERROR]] + "Send request error", error, ErrorCode.ERROR_aSR_bPH_HSK_ERROR, this._send_request.name)
                });
        }

        // Convert request into a JSON string and encrypt request
        request.with_request_id(await this._request_id_generator.generate_id()).with_terminal_uuid(this._session.terminal_uuid).with_request_time_millis(Math.round(new Date().getTime()));
        const raw_request: string = JSON.stringify(request);
        const [payload, seq]: [Buffer, number] = this._session.chiper.encrypt(raw_request);
        const url: string = this._base_url + '/request';
        
        const response: TapoResponse<Json_T> = await this.session_post(url, payload, this._session.get_cookies()[1], {'seq': seq})
            .then(async (value: [AxiosResponse, Buffer]): Promise<TapoResponse<Json_T>> => {
            
                // Check handled errors
                if (value[0].status != 200) {
                    if (this._debug) console.debug('Query failed after successful authentication at ' + new Date().getTime() + '. Host is ' + this._host + '. Available attempts count is ' + retry + '. Sequence is ' + seq + '. Response status is ' + value[0].status + '. Request was ' + raw_request);
                    if (value[0].status == 403) {
                        this.close(false);
                        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_DEV_FORBID]] + "Forbidden error after completing handshake", null, ErrorCode.ERROR_aSR_DEV_FORBID, this._send_request.name)
                    } else {
                        this.close(false);
                        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_DEV_GENERAL]] + "Device " + this._host + " error code " + value[0].status + " with seq " + seq, null, ErrorCode.ERROR_aSR_DEV_GENERAL, this._send_request.name)
                    }
                } else {
                    const svr_answer: TapoResponse<Json_T> = await (new TapoResponse<Json_T>()).try_from_json(JSON.parse(this._session.chiper.decrypt(value[1])))
                        .then((value: TapoResponse<Json_T>): TapoResponse<Json_T> => { return value })
                        .catch((error: TapoError) => { throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_GENERAL]] + 'Functional error - ' + error.message, error, ErrorCode.ERROR_FUNC_GENERAL, this._send_request.name) });
                    return svr_answer;
                }
            })
            .catch((error: TapoError) => {
                this.close(false);
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bSP_REQ_ERR]] + "Request error - Device " + this._host +  " with seq " + seq + " - Request: " + raw_request, error, ErrorCode.ERROR_aSR_bSP_REQ_ERR, this._send_request.name);
            });

        // Return response
        return response;
    }

    // Private operations with the session
    public async close(change_agent?: boolean) {

        // Process parameters
        const change: boolean = (typeof(change_agent) == 'undefined' ? false : change_agent);
        
        // Invalidate the session if it is not null, destroy used sockets and reinitiate axios if not kept
        if (this._session != null) this._session.invalidate();
        this._http_agent.destroy();
        if (change) {
            this._keep_alive = !(this._keep_alive);
            this._http_agent = (new URL(this._base_url).protocol == 'https:' ? new https.Agent({ keepAlive: this._keep_alive, timeout: AXIOS_TIMEOUT }) : new http.Agent({ keepAlive: this._keep_alive, timeout: AXIOS_TIMEOUT }));
        }
    }
}

// Class for Klap Sessions
export class KlapSession extends TapoSession {
    
    // Parameter defining the session data
    public chiper: KlapChiper;
    public session_id: string;
    public expire_at: number;
    public handshake_complete: boolean;
    public terminal_uuid: string;

    // Constructor to initialize the class
    constructor(session: string, timeout: number, expire?: boolean, terminal?: string, hsk?: boolean, chip?: KlapChiper) {
        super();
        this.chiper = (typeof(chip) == 'undefined' ? null : chip);
        this.session_id = session;
        this.expire_at = (((typeof(expire) == 'undefined') || (!expire)) ? new Date().getTime() + timeout*1000 : timeout);
        this.handshake_complete = (((typeof(hsk) == 'undefined') || (!hsk)) ? false : hsk);
        this.terminal_uuid = (typeof(terminal) == 'undefined' ? null : terminal);

        // Set the properties to false to avoid any change or access once created
        Object.defineProperty(this, 'session_id', {enumerable: false});
    }

    // Public method to get the cookies
    public get_cookies(): [Json_T, string] {
        return [{"TP_SESSIONID": this.session_id}, 'TP_SESSIONID=' + this.session_id];
    }

    // Public method to check if handshake has expired
    public is_handshake_session_expired(): boolean {
        return ((this.expire_at - new Date().getTime()) <= (40*1000));
    }

    // Public method to invalidate the session
    public invalidate(): void {
        this.session_id = null;
        this.handshake_complete = false;
    }

    // Public method to complete handshake and assign 'chiper'
    public complete_handshake(chiper: KlapChiper): KlapSession {
        this.handshake_complete = true;
        this.chiper = chiper;
        return this;
    }

}

// Class for Klap Chipper methods
export class KlapChiper extends TapoChiper {

    //Parameters defining the chiper of the session   
    public _key: Buffer;  // Key - Algorithm of bytes (128 bits)
    public _iv: Buffer;   // Initialization vector - First 12 bytes of sha256
    public _seq: number;  // Sequence - Last 4 bytes of sha256
    public _sig: Buffer;  // Prefix of 28 bytes to use in each request 

    // Constructor to initialize the class
    constructor(local_seed: Buffer, remote_seed: Buffer, user_hash: Buffer) {
        super();
        this._key = this._key_derive(local_seed, remote_seed, user_hash);
        [this._iv, this._seq] = this._iv_derive(local_seed, remote_seed, user_hash);
        this._sig = this._sig_derive(local_seed, remote_seed, user_hash);

        // Set the properties to false to avoid any change or access once created
        Object.defineProperty(this, '_key', {enumerable: false});
        Object.defineProperty(this, '_iv', {enumerable: false});
        Object.defineProperty(this, '_seq', {enumerable: false});
        Object.defineProperty(this, '_sig', {enumerable: false});
    }

    // Public method to encrypt
    public encrypt(msg: string | Buffer): [Buffer, number] {
        this._seq = this._seq + 1;
        if (typeof msg == 'string') {
            msg = Buffer.from(new TextEncoder().encode(msg));
        }
        if (!(msg instanceof Buffer)) throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_KL_ENCRYPT_FMT]] + "El tipo no es Buffer - " + typeof(msg), null, ErrorCode.ERROR_KL_ENCRYPT_FMT, this.encrypt.name) ;
        const cipher: Cipher = createCipheriv(AES_CIPHER_ALGORITHM, this._key, this._iv_seq()).setAutoPadding(true);
        const encryptor = cipher.update(msg);
        const final = cipher.final();
        const ciphertext = Buffer.concat([encryptor,final]);
        const hash = createHash('sha256');
        hash.update(Buffer.concat([this._sig, Buffer.from(this._seq.toString(16), 'hex'), ciphertext]));
        const signature = hash.digest();
        return [Buffer.concat([signature, ciphertext]), this._seq];
    }

    // Public method to decrypt
    public decrypt(msg: Buffer): string {
        const cipher: Cipher = createDecipheriv(AES_CIPHER_ALGORITHM, this._key, this._iv_seq()).setAutoPadding(true);
        const plaintextbytes = Buffer.concat([cipher.update(msg.subarray(32)), cipher.final()]);
        return plaintextbytes.toString();
    }

    // Private method to derive the key
    private _key_derive(local_seed: Buffer, remote_seed: Buffer, user_hash: Buffer): Buffer {
        const payload: Uint8Array = new Uint8Array([...Buffer.from("lsk"), ...local_seed, ...remote_seed, ...user_hash]);
        const hash: Buffer = createHash("sha256").update(payload).digest();
        return hash.subarray(0, 16);
    }

    private _iv_derive(local_seed: Buffer, remote_seed: Buffer, user_hash: Buffer): [Buffer, number] {
        const payload: Uint8Array = new Uint8Array([...Buffer.from("iv"), ...local_seed, ...remote_seed, ...user_hash]);
        const fulliv: Buffer = createHash("sha256").update(payload).digest();
        const seq: number = fulliv.subarray(fulliv.length-4).readInt32BE();
        return [fulliv.subarray(0, 12), seq];
    }

    private _sig_derive(local_seed: Buffer, remote_seed: Buffer, user_hash: Buffer): Buffer {
        const payload: Uint8Array = new Uint8Array([...Buffer.from("ldk"), ...local_seed, ...remote_seed, ...user_hash]);
        const hash: Buffer = createHash("sha256").update(payload).digest();
        return hash.subarray(0, 28);
    }

    private _iv_seq(): Buffer {
        const seq: Buffer = Buffer.alloc(4);
        seq.writeInt32BE(this._seq);
        const iv: Uint8Array = new Uint8Array([...this._iv, ...seq]);
        if (iv.length != 16) throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_KL_ENCRYPT_IV_LENGTH]] + "La longitud es " + iv.length, null, ErrorCode.ERROR_KL_ENCRYPT_IV_LENGTH, this._iv_seq.name);
        return (iv as Buffer);
    }
}

// ****************************************************
// ***  KLAP CLASSES TO DEFINE PASSTHROUGH PROTOCOL ***
// ****************************************************
// Class for Passthrough Protocol definition
export class PassthroughProtocol extends TapoProtocol {

    // Parameters defining the Tapo Passthrough Protocol
    public _base_url: string;
    public _host: string;
    public _auth_credential: AuthCredential;
    public _http_session: AxiosInstance;
    public _http_agent: http.Agent | https.Agent;
    public _session: Session;
    public _jar: Json_T;
    public _request_id_generator: SnowflakeId;
    public _protocol_type: TapoProtocolType;
    public _terminal_random: boolean;
    public _keep_alive: boolean;
    public _debug: boolean;

     // Constructor to initialize the class
    constructor(auth_credential: AuthCredential, url: string, terminal_random?: boolean, keep_alive?: boolean, debug?: boolean) {
        super();
        this._base_url = url;
        this._host = (new URL(this._base_url)).hostname;
        this._session = null;
        this._jar = null;
        this._auth_credential = auth_credential;
        this._request_id_generator = new SnowflakeId(1, 1);
        this._protocol_type = TapoProtocolType.PASSTHROUGH;
        this._terminal_random = ((typeof(terminal_random) == 'undefined') ? false : terminal_random);
        this._keep_alive = ((typeof(keep_alive) == 'undefined') ? true : keep_alive);
        this._debug = (typeof(debug) == 'undefined' ? false : debug);
        try {
            this._http_agent = (new URL(this._base_url).protocol == 'https:' ? new https.Agent({ keepAlive: this._keep_alive, timeout: AXIOS_TIMEOUT }) : new http.Agent({ keepAlive: this._keep_alive, timeout: AXIOS_TIMEOUT }));
            this._http_session = axios.create({timeout: AXIOS_TIMEOUT, httpAgent: this._http_agent, validateStatus: () => {return true}, proxy: false});
        } catch (err) {
            new TapoError(ErrorMsg[ErrorCode[ErrorCode.GENERIC_ERROR]] + 'Agent error - ' + err, null, ErrorCode.GENERIC_ERROR, this.constructor.name)
        }

        // Set the properties to false to avoid any change or access once created
        if (!this._debug) {
            Object.defineProperty(this, '_auth_credential', {enumerable: false});
            Object.defineProperty(this, '_http_session', {enumerable: false});
            Object.defineProperty(this, '_http_agent', {enumerable: false});
            Object.defineProperty(this, '_session', {enumerable: false});
            Object.defineProperty(this, '_jar', {enumerable: false});
            Object.defineProperty(this, '_request_id_generator', {enumerable: false});
            Object.defineProperty(this, '_keep_alive', {enumerable: false});
            Object.defineProperty(this, '_debug', {enumerable: false});
        }
    }

    // Public methods used in the class to manage encryption and ciphering
    public async create_key_pair(key_size?: number): Promise<KeyPairKeyObjectResult> {

        // Handle the parameter
        const k_size: number = (typeof(key_size) == 'undefined' ? 1024 : key_size);

        // Generate keys
        const RSA_OPTIONS = {
            modulusLength: k_size,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs1',
                format: 'pem',
                cipher: AES_CIPHER_ALGORITHM,
                passphrase: PASSPHRASE
            }
        };
        const generateKeyPair_prom = promisify(generateKeyPair);
        const pair: KeyPairKeyObjectResult = await generateKeyPair_prom(RSA_CIPHER_ALGORITHM, RSA_OPTIONS);
        return pair;
    }
 
    // Private method to post a session
    public async session_post(url: string, data: any, cookies?: any, params?: any): Promise<AxiosResponse> {
        this._jar = null;
        const common_headers: Json_T = { "Content-Type": "application/json", "requestByApp": "true", "Accept": "application/json" };
        const headers: Json_T = {...common_headers, ...(typeof(cookies) == 'undefined'?undefined:{'Cookie': cookies})};
        const config: AxiosRequestConfig = {url: url, method: 'post', data: data, headers: headers, params: (typeof(params) == 'undefined'?undefined:params)};
        const response: AxiosResponse = await this._http_session.request(config)
            .then((value: AxiosResponse): AxiosResponse => {
                if (value.status != 200) {
                    this._http_agent.destroy();
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSP_bAX_REQ_FORBID]] + 'URL error - ' + value.statusText + " - " + value.status, null, ErrorCode.ERROR_aSP_bAX_REQ_FORBID, this.session_post.name);
                } else {

                    // Get the cookies
                    if (value.headers.hasOwnProperty('set-cookie')) {
                        const cookies = value.headers['set-cookie'][0].split(';');
                        for (let i=0; i < cookies.length; i++ ) {
                            if (cookies[i].includes('=')) {
                                this._jar = {...this._jar, [cookies[i].split('=')[0]]: cookies[i].split('=')[1]}
                            }    
                        }
                    }
                                        
                    // Return value
                    return value
                }
            })
            .catch((error: AxiosError) => {
                this._http_agent.destroy();
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSP_bAX_REQ_ERR]] + 'Session_post error - ' + error.message, new TapoError().axios_to_tapo(error), ErrorCode.ERROR_aSP_bAX_REQ_ERR, this.session_post.name)
            });
        return response; 
    }

    // Private method Handshake to perform the full Handshake and get a valid Session
    public async perform_handshake(url?: string): Promise<Session> {
              
        // Print debug messages
        if (this._debug) console.debug("Will perform handshaking...");
        if (this._debug) console.debug("Generating keypair");

        // Prepare parameters
        const req_url: string = (typeof(url) == 'undefined' ? this._base_url : url);
        let session: Session = null;

        // Get the key pair and handshake parameters
        const key_pair: KeyPairKeyObjectResult = await this.create_key_pair();
        const handshake_params: HandshakeParams = new HandshakeParams(key_pair.publicKey);
        if (this._debug) console.debug("Handshake params: " + JSON.stringify(handshake_params));

        // Create the Tapo request
        const request: TapoRequest = new TapoRequest().handshake(handshake_params);
        if (this._debug) console.debug("Request " + JSON.stringify(request));

        // Get the response from the device
        const response: Session = await this.session_post(req_url, request)
            .then((value: AxiosResponse): Session => {
                if (this._debug) console.debug("Handshake posted " + new Date().getTime() + ". Host is " + this._host + ", Response status is " + value.status + ", Request was " + JSON.stringify(request));
                if (value.status != 200) {
                    this.close(false);
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH_bSP_HSK_REJ]] + "Device responded with " + value.status + " to handshake", null, ErrorCode.ERROR_aPH_bSP_HSK_REJ, this.perform_handshake.name);
                } else {
                    
                    // Read the Session ID and timeout and create a session - still invalid
                    if (this._debug) console.debug("Handshake got cookies: ..." + JSON.stringify(this._jar));
                    const session_id: string = this._jar[TP_SESSION_COOKIE_NAME];
                    const timeout: number = parseInt(this._jar["TIMEOUT"],10);
                    const terminal_uuid = (this._terminal_random ? webcrypto.randomUUID() : uuidv4());
                    session = new Session(session_id, timeout, false, req_url, terminal_uuid, key_pair);
                    
                    // Get the device key and complete the session if everything is ok
                    if (this._debug) console.debug("Decoding handshake key ...");
                    const handshake_key: string = value.data.result.key;
                    try{
                        const chiper: Chiper = new Chiper().create_from_keypair(handshake_key, key_pair);
                        return session.complete_handshake(chiper);
                    } catch (error){
                        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aPH_bSP_HSK_FORBID]] + "Unable to extract device key from handshake - " + error.message, null, ErrorCode.ERROR_aPH_bSP_HSK_FORBID, this.perform_handshake.name );
                    };
                };
            })
            .catch((error: Error) => {
                this.close(false);
                throw new Error("Device responded with " + error.message + " to handshake");
            });
        return response;
    }

    // Public method to login with or without version 2 parameters
    public async _login_with_version(is_trying_v2?: boolean): Promise<Session> {
        
        // Check the parameter
        const v2: boolean = (((typeof(is_trying_v2) == 'undefined') || (!is_trying_v2)) ? false : is_trying_v2);

        // Try to perform the handshake and get a valid session
        const session: Session = await this.perform_handshake()
            .then(async (ses_value: Session): Promise<Session> => {
                
                // Check if the session has a valid handshake
                if (!ses_value.is_handshake_session_expired()) {

                    // Try to login with version 2 first
                    const login_request: TapoRequest = new TapoRequest().login(this._auth_credential, v2);
                    const token: string = await this.send(login_request, ses_value)
                        .then(async (log_value: TapoResponse<Json_T>): Promise<string> => {
                            if (log_value.result.hasOwnProperty('token')) {
                                return log_value.result.token;
                            } else {
                                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aLG_bS_TOKEN_NOT_FOUND]] + "Token not found - " + JSON.stringify(log_value), null, ErrorCode.ERROR_aLG_bS_TOKEN_NOT_FOUND, this._login_with_version.name)
                            }
                        })
                        .catch(async (error: TapoError): Promise<string> => {
                            if (!v2) {
                                return (await this._login_with_version(true)).token;
                            } else {
                                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aLG_bS_TOKEN_ERROR]] + "Token error - " + error.message, error, ErrorCode.ERROR_aLG_bS_TOKEN_ERROR, this._login_with_version.name)
                            }
                        });

                    // Update the token and return the session
                    ses_value.token = token;
                    return ses_value;
                } else {
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aLG_bPH_HSK_TIMEOUT]] + "Detected handshake session timeout ", null, ErrorCode.ERROR_aLG_bPH_HSK_TIMEOUT, this._login_with_version.name)
                }
            })
            .catch((error: TapoError) => {
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aLG_bPH_HSK_ERROR]] + "Handshake error - " + error.message, error, ErrorCode.ERROR_aLG_bPH_HSK_ERROR, this._login_with_version.name)
            });
        return session;
    }

    // Public method to send a request with 3 retries
    public async send_request( request: TapoRequest, retry?: number ): Promise<TapoResponse<Json_T>> {
        const retr = (typeof(retry) == 'undefined' ? 3 : retry);
		const response = await this._send_request(request, retr)
            .then((value: TapoResponse<Json_T>) => { return value})
            .catch(async (error: TapoError) => {
                if (retr > 0) {
                    try {
                        return await this.send_request(request, retr - 1);
                    } catch (error) {
                        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bSR_RET_ERR]] + "Send request failed - Retry nº " + retr.toString(), error, ErrorCode.ERROR_aSR_bSR_RET_ERR, this.send_request.name);
                    }
                } else {
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bSR_MAX_RET]] + "Send request max retries failed - " + error.message, error, ErrorCode.ERROR_aSR_bSR_MAX_RET, this.send_request.name);
                }
            });
        return response; 
	}

    // Public method to send every request
    public async _send_request( request: TapoRequest, retry?: number ): Promise<TapoResponse<Json_T>> {

        // Check if there is a valid session and get one if not ready
        this._session = (((this._session == null) || (this._session.token == null)) ? await this._login_with_version() : this._session);
        
        // Prepare request with terminal and timestamp and send it
        request.with_terminal_uuid(this._session.terminal_uuid).with_request_time_millis(Math.round(new Date().getTime()));
        return await this.send(request);
    }

    public async send(request: TapoRequest, session?: Session): Promise<TapoResponse<Json_T>> {
        
        // Process the optional parameters
        const send_session: Session = (typeof(session) == 'undefined' ? this._session : session);

        // Prepare request to be sent
        request.with_request_id(await this._request_id_generator.generate_id()).with_request_time_millis(Math.round(new Date().getTime())).with_terminal_uuid(send_session.terminal_uuid);
        const raw_request: string = JSON.stringify(request);
        if (this._debug) console.debug("Raw request " + raw_request);

        // Encrypt and prepare request for secure passthrough
        const encrypted_request = send_session.chiper.encrypt(raw_request);
        const passthrough_request: TapoRequest = new TapoRequest().secure_passthrough(new SecurePassthroughParams(encrypted_request));
        if (this._debug) console.debug("Request body " + JSON.stringify(passthrough_request));

        // Prepare url to be used and send request
        const url: string = send_session.url + '?token=' + send_session.token;
        const response: TapoResponse<Json_T> = await this.session_post(url, passthrough_request, send_session.get_cookies()[1])
            .then(async (value: AxiosResponse): Promise<TapoResponse<Json_T>> => {
                if (this._debug) console.debug("Handshake posted " + new Date().getTime() + ". Host is " + this._host + ", Response status is " + value.status + ", Request was " + JSON.stringify(passthrough_request));
                if (value.status != 200) {
                    this.close(false);
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bSP_REJ]] + "Device responded with " + value.status + " to request", null, ErrorCode.ERROR_aSR_bSP_REJ, this.send.name);
                } else {
                    const svr_answer: TapoResponse<Json_T> = await (new TapoResponse<Json_T>()).try_from_json(JSON.parse(JSON.stringify(send_session.chiper.decrypt(value.data.result.response))))
                        .then((value: TapoResponse<Json_T>): TapoResponse<Json_T> => { return value })
                        .catch((error: TapoError) => { throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_FUNC_GENERAL]] + 'Functional error - ' + error.message, error, ErrorCode.ERROR_FUNC_GENERAL, this._send_request.name) });
                    return svr_answer;
                }
            })
            .catch((error: TapoError) => {
                this.close(false);
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_aSR_bSP_REQ_ERR]] + "Device responded with " + error.message + " to request " + raw_request, error, ErrorCode.ERROR_aSR_bSP_REQ_ERR, this.send.name);
            });
        
        // Return response
        return response;
    }

    // Private operations with the session
    public async close(change_agent?: boolean) {

        // Process parameters
        const change: boolean = (typeof(change_agent) == 'undefined' ? false : change_agent);
        
        // Invalidate the session if it is not null, destroy used sockets and reinitiate axios if not kept
        if (this._session != null) this._session.invalidate();
        this._http_agent.destroy();
        if (change) {
            this._keep_alive = !(this._keep_alive);
            this._http_agent = (new URL(this._base_url).protocol == 'https:' ? new https.Agent({ keepAlive: this._keep_alive, timeout: AXIOS_TIMEOUT }) : new http.Agent({ keepAlive: this._keep_alive, timeout: AXIOS_TIMEOUT }));
        }
    }
}

// Class for PassthroughProtocol Session
export class Session extends TapoSession{

    // Parameters defining the Session class
    public chiper: Chiper;
    public session_id: string;
    public expire_at: number;
    public handshake_complete: boolean;
    public url: string;
    public key_pair: KeyPairKeyObjectResult;
    public token: string;
    public terminal_uuid: string;

    // Constructor to initialize the class
    constructor(session: string, timeout: number, expire?: boolean, url?: string, terminal?: string, keypair?: KeyPairKeyObjectResult, hsk_req?: boolean, chip?: Chiper) {
        super();
        this.chiper = (typeof(chip) == 'undefined' ? null : chip);
        this.session_id = session;
        this.expire_at = (((typeof(expire) == 'undefined') || (!expire)) ? ((new Date()).getTime() + timeout)*1000 : timeout);
        this.handshake_complete = (((typeof(hsk_req) == 'undefined') || (!hsk_req)) ? true : !hsk_req);
        this.token = null;
        this.key_pair = (typeof(keypair) == 'undefined' ? null : keypair);
        this.terminal_uuid = (typeof(terminal) == 'undefined' ? null : terminal);
        this.url = (typeof(url) == 'undefined' ? null : url);

        // Set the properties to false to avoid any change or access once created
        Object.defineProperty(this, 'session_id', {enumerable: false});
        Object.defineProperty(this, 'key_pair', {enumerable: false});
        Object.defineProperty(this, 'token', {enumerable: false});
    }

    // Public method to get the cookies
    public get_cookies(): [Json_T, string] {
        return [{"TP_SESSIONID": this.session_id}, 'TP_SESSIONID=' + this.session_id];
    }

    // Public method to check if handshake has expired
    public is_handshake_session_expired(): boolean {
        return (!this.handshake_complete) || ((this.expire_at - new Date().getTime()) <= (40*1000));
    }

    // Public method to invalidate the session
    public invalidate(): void {
        this.handshake_complete = false;
        this.token = null;
    }

    // Public method to complete handshake and assign 'chiper'
    public complete_handshake(chiper: Chiper): Session {
        this.chiper = chiper;
        this.handshake_complete = true;
        return this;
    }
}

// Class for Klap Chipper methods
export class Chiper extends TapoChiper {
 
    //Parameters defining the chiper of the session   
    public _key: Buffer;  // Key - Algorithm of bytes (128 bits)
    public _iv: Buffer;   // Initialization vector - First 12 bytes of sha256
    public cipher: Cipher;   // Objeto para cifrado

    // Constructor to initialize the class
    constructor(key?: Buffer, iv?: Buffer) {
        super();
        this._key = (typeof(key) == 'undefined' ? null : key);
        this._iv = (typeof(iv) == 'undefined' ? null : iv);
        if ((this._key != null) && (this._iv != null)) {
            this.cipher = createCipheriv(AES_CIPHER_ALGORITHM, key, iv).setAutoPadding(true)
        } else {
            this.cipher = null
        }

        // Set the properties to false to avoid any change or access once created
        Object.defineProperty(this, '_key', {enumerable: false});
        Object.defineProperty(this, '_iv', {enumerable: false});
        Object.defineProperty(this, 'cipher', {enumerable: false});
    }

    // Public method to create from keypair
    public create_from_keypair(handshake_key: string, keypair: KeyPairKeyObjectResult): Chiper {
        //const private_key: Buffer = Buffer.from(keypair.privateKey, 'base64');
        const key_and_iv: Buffer = this.readDeviceKey(handshake_key, keypair.privateKey);
        if (key_and_iv === null) {
            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_CH_UNABLE_KEYS]] + "Decryption failed!", null, ErrorCode.ERROR_CH_UNABLE_KEYS, this.create_from_keypair.name);
        } else {
            this._key =  key_and_iv.subarray(0,16);
            this._iv = key_and_iv.subarray(16, 32);
            this.cipher = createCipheriv(AES_CIPHER_ALGORITHM, this._key, this._iv).setAutoPadding(true);
            return this;
        }
    }

    // Private method to read the device key from handshake info    
    private readDeviceKey(pemKey: string, privateKey: KeyObject) : Buffer {
        const keyBytes = Buffer.from(pemKey, 'base64');
        const deviceKey = privateDecrypt({
            key: privateKey,
            padding: constants.RSA_PKCS1_PADDING,
            passphrase: PASSPHRASE,
        }, keyBytes);
        
        return deviceKey;
    }
    
    // Public method to decrypt
    public decrypt(msg: string | Buffer): string {
        if (typeof msg == 'string') {
            msg = Buffer.from(msg, 'base64');
        }
        const cipher = createDecipheriv(AES_CIPHER_ALGORITHM, this._key, this._iv).setAutoPadding(true);
        const plaintextbytes = Buffer.concat([cipher.update(msg), cipher.final()]);
        return JSON.parse(plaintextbytes.toString());
    }
    
    // Public method to encrypt
    public encrypt(msg: string | Buffer): string {
        if (typeof msg == 'string') {
            msg = Buffer.from(msg);
        }
        if (!(msg instanceof Buffer)) throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_KL_ENCRYPT_FMT]] + "El tipo no es Buffer - " + typeof(msg), null, ErrorCode.ERROR_KL_ENCRYPT_FMT, this.encrypt.name) ;
        const cipher = createCipheriv(AES_CIPHER_ALGORITHM, this._key, this._iv).setAutoPadding(true);
        const encryptor = cipher.update(msg);
        const final = cipher.final();
        const ciphertext = Buffer.concat([encryptor,final]);
        return ciphertext.toString('base64');
    }
}

export class SnowflakeId{

    // Parameters defining the class
    private EPOCH = 1420041600000;  // Custom epoch (in milliseconds)
    private WORKER_ID_BITS = 5;
    private DATA_CENTER_ID_BITS = 5;
    private SEQUENCE_BITS = 12;
    private MAX_WORKER_ID: number = (1 << this.WORKER_ID_BITS) - 1;
    private MAX_DATA_CENTER_ID: number = (1 << this.DATA_CENTER_ID_BITS) - 1;
    private SEQUENCE_MASK: number = (1 << this.SEQUENCE_BITS) - 1;

    public worker_id: number;
    public data_center_id: number;
    public sequence: number;
    public last_timestamp: number;

    // Constructor of the class
    constructor(worker_id: number, data_certer_id: number) {
        
        // Check the limits
        if ((worker_id > this.MAX_WORKER_ID) || (worker_id < 0)) {
            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_SNOW_WORKER_ID]] + "Worker ID can't be greater than " + this.MAX_WORKER_ID + " or less than 0", null, ErrorCode.ERROR_SNOW_WORKER_ID, 'SnowflakeId')
        }
        if ((data_certer_id > this.MAX_DATA_CENTER_ID) || (data_certer_id < 0)) {
            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_SNOW_DATA_CENTER_ID]] + "Data center ID can't be greater than " + this.MAX_DATA_CENTER_ID + " or less than 0", null, ErrorCode.ERROR_SNOW_DATA_CENTER_ID, 'SnowflakeId')
        }

        // Assign the values
        this.worker_id = worker_id;
        this.data_center_id = data_certer_id;
        this.sequence = 0;
        this.last_timestamp = -1;
    }

    // Public methods defined in the class
    public async generate_id() {

        // Get current timestamp in milliseconds
        let timestamp: number = new Date().getTime();

        // Check timestamp against last one
        if (timestamp < this.last_timestamp) {
            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_SNOW_INVALID_TIME_ID]] + "Clock moved backwards. Refusing to generate ID.", null, ErrorCode.ERROR_SNOW_INVALID_TIME_ID, this.generate_id.name)
        } else if (timestamp == this.last_timestamp) {

            // Within the same millisecond increment the sequence number
            this.sequence = (this.sequence + 1) & this.SEQUENCE_MASK;
            if (this.sequence == 0) {

                // Sequence exceeds its bit range. Wait until the next millisecond
                timestamp = await this._wait_next_millis(this.last_timestamp)
            }
        } else {

            // New millisecond, reset the sequence number
            this.sequence = 0;
        }

        // Generate and return the final ID
        return (((timestamp - this.EPOCH) << (this.WORKER_ID_BITS + this.SEQUENCE_BITS + this.DATA_CENTER_ID_BITS)) | (this.data_center_id << (this.SEQUENCE_BITS + this.WORKER_ID_BITS)) | (this.worker_id << this.SEQUENCE_BITS) | this.sequence);
    }

    // Private methods defined in the class
    private async _wait_next_millis(last_timestamp: number): Promise<number> {
        let timestamp: number = new Date().getTime();
        do {
            timestamp = new Date().getTime()
        } while (timestamp <= last_timestamp);
        return timestamp;
    }
}

// ********************************************
// ***  KLAP CLASSES TO DEFINE TAPO DEVICES ***
// ********************************************
// Enum for Tapo Devices
export enum TapoDevicesType {
    PLUG = 'SMART.TAPOPLUG',
    BULB = 'SMART.TAPOBULB',
    CAMERA = 'SMART.IPCAMERA'
}

// Class for Base Tapo Device
export class TapoDevice {

    // Define parameters of the class
    public _api: TapoClient;
    public deviceType: string;
    public fwVer: string;
    public appServerUrl: string;
    public deviceRegion: string;
    public deviceId: string;
    public deviceName: string;
    public deviceHwVer: string;
    public alias: string;
    public deviceMac: string;
    public oemId: string;
    public deviceModel: string;
    public hwId: string;
    public fwId: string;
    public isSameRegion: boolean;
    public status: number;
    public ip: string;
    public terminal_random?: boolean;
    public _debug: boolean;
    public _keep_alive: boolean;

    // Constructor to initialize the class
    constructor(terminal_random?: boolean, api?: TapoClient, keep_alive?: boolean, debug?: boolean) {
        this._api = api;
        this.terminal_random = (typeof(terminal_random) == 'undefined' ? false : terminal_random);
        this._debug = (typeof(debug) == 'undefined' ? false : debug);
        this._keep_alive = (typeof(keep_alive) == 'undefined' ? true : keep_alive);

        // Set the properties to false to avoid any change or access once created
        if (!debug) {
            Object.defineProperty(this, '_debug', {enumerable: false});
            Object.defineProperty(this, '_keep_alive', {enumerable: false});
        }
    }

    // Methods to be used by the class
    public async raw_command(method: string, params: Json_T, protocol?: TapoProtocolType): Promise<Json_T> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        return await this._api.execute_raw_request(new TapoRequest(method, params), proto)
    }
    
    public async get_device_info(protocol?: TapoProtocolType): Promise<TapoDeviceInfo> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        const result: Json_T = this.get_state_as_json(proto);
        return <TapoDeviceInfo>result;
    }

    public async get_energy_usage(protocol?: TapoProtocolType): Promise<TapoEnergyUsage> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        const result: Json_T = this._api.get_energy_usage(proto);
        return <TapoEnergyUsage>result;
    }

    public async turn_onoff_device(status: boolean, protocol?: TapoProtocolType): Promise<Json_T> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        const result: Json_T = this._api.turn_onoff_device(status, proto);
        return result;
    }
   
    public async set_color_device(color: string, protocol?: TapoProtocolType): Promise<Json_T> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        const result: Json_T = this._api.set_color_device(color, proto);
        return result;
    }

    public async set_brightness_device(level: number, protocol?: TapoProtocolType): Promise<Json_T> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        const result: Json_T = this._api.set_brightness_device(level, proto);
        return result;
    }

    public async send_request(request: TapoRequest, protocol?: TapoProtocolType): Promise<Json_T> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        const result: Json_T = this._api.send_request(request, proto);
        return result;
    }

    public async get_state_as_json(protocol?: TapoProtocolType): Promise<Json_T> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        return await this._api.get_device_info(proto)
    }

    public async get_component_negotiation(protocol?: TapoProtocolType): Promise<Components> {
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined'?TapoProtocolType.AUTO:protocol);
        return await this._api.get_component_negotiation(proto)
    }

    public async get_device_by_IP(auth_credential: AuthCredential, ip: string, protocol?: TapoProtocolType): Promise<TapoDevice> {

        // Process the parameters
        const proto: TapoProtocolType = (typeof(protocol) == 'undefined' ? undefined : protocol);

        // Update the ip of the device
        this.ip = ip;

        // Create the client
        this._api = new TapoClient(auth_credential, this.ip, proto, this.terminal_random, this._keep_alive, this._debug);

        // Return device
        return this;
    }

    public async get_device_by_alias(auth_credential: AuthCredential, alias: string, range_ip?: string): Promise<TapoDevice> {

        // Process the parameters
        const range: string = (typeof(range_ip) == 'undefined' ? undefined : range_ip);

        // Connect to the cloud to get the list of devices
        const devices: Array<TapoDevice> = await this.list_devices(await this.cloud_login(auth_credential));

        //Match the device by alias
        if (devices !== undefined) {
            for (const items of devices) {
                if (items.alias === alias) {
                    items.ip = await items.resolve_MAC_to_IP(items.deviceMac, range);
                    return await items.get_device_by_IP(auth_credential, items.ip);
                }
            }
        } else {
            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_CLOUD_NO_DEVICE_LIST]] + "Failed to get tapo device list", null, ErrorCode.ERROR_CLOUD_NO_DEVICE_LIST, this.get_device_by_alias.name);
        }

        // Return error not found
        throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_ALIAS_NOT_FOUND]] + 'Alias not found - ' + alias, null, ErrorCode.ERROR_ALIAS_NOT_FOUND, this.get_device_by_alias.name);
    }

    public async cloud_login(auth_credential: AuthCredential): Promise<string> {
  
        // Prepare the request to connect to Cloud account
        const request: TapoRequest = new TapoRequest().cloud_login(auth_credential);
        const config: AxiosRequestConfig = {url: CLOUD_URL, method: 'post', data: request, timeout: AXIOS_TIMEOUT, httpAgent: new http.Agent({ keepAlive: false }), validateStatus: () => {return true}, proxy: false};
        const response: TapoResponse<Json_T> = await axios.request(config)
            .then(async (value: AxiosResponse): Promise<TapoResponse<Json_T>> => {
                if (value.status != 200) {
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_CLOUD_CONN_REJ]] + 'Tapo Cloud server - Unable to connect: ' + value.statusText, null, ErrorCode.ERROR_CLOUD_CONN_REJ, this.cloud_login.name)
                } else {
                    const svr_answer: TapoResponse<Json_T> = await (new TapoResponse<Json_T>()).try_from_json(JSON.parse(JSON.stringify(value.data)));
                    return svr_answer;
                }
            })
            .catch((error: AxiosError) => {
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_AXIOS_ERROR]] + 'Tapo Cloud server error - ' + error.message, new TapoError().axios_to_tapo(error), ErrorCode.ERROR_AXIOS_ERROR, this.cloud_login.name)
            });
        
        // Return collected Cloud token
        return response.result.token;
    } 

    public async list_devices(cloudToken: string): Promise<Array<TapoDevice>> {

        // Prepare the request to get the list
        const request: TapoRequest = new TapoRequest().cloud_list_devices();
        const config: AxiosRequestConfig = {url: CLOUD_URL + '?token=' + cloudToken, method: 'post', data: request, timeout: AXIOS_TIMEOUT, httpAgent: new http.Agent({ keepAlive: false }), validateStatus: () => {return true}, proxy: false};
        const response: TapoResponse<Json_T> = await axios.request(config)
            .then(async (value: AxiosResponse): Promise<TapoResponse<Json_T>> => {
                if (value.status != 200) {
                    throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_CLOUD_CONN_REJ]] + 'Tapo Cloud server - Unable to connect: ' + value.statusText, null, ErrorCode.ERROR_CLOUD_CONN_REJ, this.list_devices.name)
                } else {
                    const svr_answer: TapoResponse<Json_T> = await (new TapoResponse<Json_T>()).try_from_json(JSON.parse(JSON.stringify(value.data)));
                    return svr_answer;
                }
            })
            .catch((error: AxiosError) => {
                throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_AXIOS_ERROR]] + 'Tapo Cloud server error - ' + error.message, new TapoError().axios_to_tapo(error), ErrorCode.ERROR_AXIOS_ERROR, this.list_devices.name)
            });
    
        // Return a mapping of the list
        return Promise.all(response.result.deviceList.map(async (deviceInfo: Json_T) => this.augment_TapoDevice(deviceInfo)));
    }

    public async list_devices_by_type(cloudToken: string, deviceType: string): Promise<Array<TapoDevice>> {
        const devices = await this.list_devices(cloudToken);
        return devices.filter(d => d.deviceType === deviceType);
    }

    // Define private methods used by the class
    private async augment_TapoDevice(deviceInfo: Json_T): Promise<TapoDevice> {

        // Get an instance to a new Tapo device and copy all info in deviceInfo
        const device: TapoDevice = new TapoDevice(this.terminal_random);
        try {
            for (const [key, value] of Object.entries(deviceInfo)) { device[key] = value }
        } catch (error) {
            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.ERROR_DEVICE_INFO]] + 'Error on Tapo Device information - ' + error.message, null, ErrorCode.ERROR_DEVICE_INFO, this.augment_TapoDevice.name)
        }

        // Check if it is a Tapo Device
        if (this.isTapoDevice(deviceInfo.deviceType)) {
            device.alias = Buffer.from(deviceInfo.alias, 'base64').toString();
        }
        
        // Return the new TapoDevice object
          return device;
    }

    private isTapoDevice(deviceType: string): boolean {
        switch (deviceType) {
            case TapoDevicesType.PLUG:
            case TapoDevicesType.BULB:
            case TapoDevicesType.CAMERA:
                return true
            default: return false
        }
    }

    private async resolve_MAC_to_IP(mac: string, range_ip?: string) :Promise<string> {
        //@ts-ignore
        const devices = await find(range_ip)
        let result : string = "";
        try {
            if (devices !== undefined) {
                result = devices.find((device) => this.tidy_MAC(device!.mac) == this.tidy_MAC(mac)).ip;
            }
            return result;
        } catch (error) {
            throw new TapoError(ErrorMsg[ErrorCode[ErrorCode.GENERIC_ERROR]] + 'MAC conversion error - ' + error.message, null, ErrorCode.GENERIC_ERROR, this.resolve_MAC_to_IP.name)
        }
    }
    
    private tidy_MAC(mac: string): string {
        return mac.replace(/:/g, '').replace(/-/g, '').toUpperCase();
    }

}

// Types for Tapo Device results
export type TapoResuls = {
    result: boolean;
    tapoDeviceInfo?: TapoDeviceInfo;
    tapoEnergyUsage?: TapoDeviceInfo | undefined;
    tapoComponents?: Components | undefined;
    tapoCommand?: Json_T | undefined;
    errorInf?: Error;
    device?: TapoDevice;
}

export type TapoDeviceInfo = {
    device_id: string;
    fw_ver: string;
    hw_ver: string;
    type: string;
    model: string;
    mac: string;
    hw_id: string;
    fw_id: string;
    oem_id: string;
    specs: string;
    device_on: boolean;
    on_time: number;
    overheated: boolean;
    nickname: string;
    location: string;
    avatar: string;
    time_usage_today: string;
    time_usage_past7: string;
    time_usage_past30: string;
    longitude: string;
    latitude: string;
    has_set_location_info: boolean;
    ip: string;
    ssid: string;
    signal_level: number;
    rssi: number;
    region: string;
    time_diff: number;
    lang: string; 
}

export type TapoEnergyUsage = TapoDeviceInfo;

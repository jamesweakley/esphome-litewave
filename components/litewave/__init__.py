"""ESPHome external component for Nanoleaf Litewave control over raw 802.15.4."""

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import automation
from esphome.components import esp32
from esphome.const import CONF_ID

CODEOWNERS = ["@jamesweakley"]
DEPENDENCIES = ["esp32"]

CONF_CHANNEL = "channel"
CONF_PAN_ID = "pan_id"
CONF_ADMIN_KEY = "admin_key"
CONF_SNIFF = "sniff"
CONF_GROUPS = "groups"
CONF_GROUP_ID = "group"
CONF_ON_SEQUENCE = "on_sequence"
CONF_ON_TOKEN = "on_token"
CONF_OFF_SEQUENCE = "off_sequence"
CONF_OFF_TOKEN = "off_token"
CONF_DIM_PLUS_SEQUENCE = "dim_plus_sequence"
CONF_DIM_PLUS_TOKEN = "dim_plus_token"
CONF_DIM_MINUS_SEQUENCE = "dim_minus_sequence"
CONF_DIM_MINUS_TOKEN = "dim_minus_token"
CONF_SHARED_SECRET = "shared_secret"
CONF_SWITCH_EUI = "switch_eui"
CONF_LIGHTS = "lights"
CONF_NAME = "name"
CONF_HOST = "host"
CONF_PAIRING_CODE = "pairing_code"
CONF_LIGHT_INDEX = "light_index"

litewave_ns = cg.esphome_ns.namespace("litewave")
LitewaveComponent = litewave_ns.class_("LitewaveComponent", cg.Component)
LitewaveGroup = litewave_ns.struct("LitewaveGroup")
LightInfo = litewave_ns.struct("LightInfo")
LitewaveSendOnAction = litewave_ns.class_("LitewaveSendOnAction", automation.Action)
LitewaveSendOffAction = litewave_ns.class_("LitewaveSendOffAction", automation.Action)
LitewaveSendDimPlusAction = litewave_ns.class_("LitewaveSendDimPlusAction", automation.Action)
LitewaveSendDimMinusAction = litewave_ns.class_("LitewaveSendDimMinusAction", automation.Action)
LitewaveProvisionLightAction = litewave_ns.class_("LitewaveProvisionLightAction", automation.Action)


def validate_token(value):
    """Validate a 14-byte hex token string."""
    value = cv.string_strict(value)
    value = value.replace(" ", "").replace(":", "").upper()
    if len(value) != 28:
        raise cv.Invalid(f"Token must be exactly 14 bytes (28 hex chars), got {len(value)} chars")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise cv.Invalid("Token must be valid hexadecimal")
    return value


def validate_shared_secret(value):
    """Validate a hex shared secret string or integer (auto zero-padded to 54 bytes / 108 hex chars)."""
    if isinstance(value, int):
        value = f"{value:x}"
    else:
        value = cv.string(value)
    value = value.replace(" ", "").replace(":", "").lower()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) > 108:
        raise cv.Invalid(f"Shared secret must be at most 54 bytes (108 hex chars), got {len(value)} chars")
    value = value.rjust(108, "0")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise cv.Invalid("Shared secret must be valid hexadecimal")
    return value


def validate_switch_eui(value):
    """Validate a 16-hex Sense+ switch EUI-64 address (or 8-hex entry)."""
    if isinstance(value, int):
        value = f"{value:x}"
    else:
        value = cv.string_strict(value)
    value = value.replace(" ", "").replace(":", "").replace("-", "").lower()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) not in (8, 16):
        raise cv.Invalid(f"Switch EUI must be 16 hex chars (EUI-64) or 8 hex chars, got {len(value)} chars")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise cv.Invalid("Switch EUI must be valid hexadecimal")
    return value


def build_switch_acl_payload(switch_eui_hex):
    """
    Derive the 10-byte TLV ACL payload for a switch EUI:
    Tag 0x01 (ControlList): 4 bytes (take(4) + takeLast(4) of EUI-64)
    Tag 0x02 (MotionList):  4 bytes (take(4) + takeLast(4) of EUI-64)
    """
    clean = switch_eui_hex.replace(":", "").replace("-", "").strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if len(clean) == 16:
        entry_hex = clean[:4] + clean[-4:]
    elif len(clean) == 8:
        entry_hex = clean
    else:
        raise cv.Invalid(f"Invalid switch EUI length: {len(clean)}")
    entry_bytes = [int(entry_hex[i : i + 2], 16) for i in range(0, len(entry_hex), 2)]
    # Tag 0x01 (len=4) + entry + Tag 0x02 (len=4) + entry
    return [0x01, len(entry_bytes)] + entry_bytes + [0x02, len(entry_bytes)] + entry_bytes


LIGHT_SCHEMA = cv.Schema(
    {
        cv.Optional(CONF_ID): cv.string_strict,
        cv.Optional(CONF_NAME, default=""): cv.string_strict,
        cv.Optional(CONF_HOST, default=""): cv.string_strict,
        cv.Required(CONF_PAIRING_CODE): cv.string_strict,
    }
)

GROUP_SCHEMA = cv.Schema(
    {
        cv.Required(CONF_ID): cv.declare_id(LitewaveGroup),
        cv.Optional(CONF_SHARED_SECRET): validate_shared_secret,
        cv.Optional(CONF_SWITCH_EUI): validate_switch_eui,
        cv.Required(CONF_ON_SEQUENCE): cv.hex_uint8_t,
        cv.Required(CONF_ON_TOKEN): validate_token,
        cv.Required(CONF_OFF_SEQUENCE): cv.hex_uint8_t,
        cv.Required(CONF_OFF_TOKEN): validate_token,
        cv.Optional(CONF_DIM_PLUS_SEQUENCE): cv.hex_uint8_t,
        cv.Optional(CONF_DIM_PLUS_TOKEN): validate_token,
        cv.Optional(CONF_DIM_MINUS_SEQUENCE): cv.hex_uint8_t,
        cv.Optional(CONF_DIM_MINUS_TOKEN): validate_token,
        cv.Optional(CONF_LIGHTS, default=[]): cv.ensure_list(LIGHT_SCHEMA),
    }
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(LitewaveComponent),
            cv.Required(CONF_CHANNEL): cv.int_range(min=11, max=26),
            cv.Required(CONF_PAN_ID): cv.hex_uint16_t,
            cv.Optional(CONF_ADMIN_KEY): cv.hex_uint16_t,
            cv.Optional(CONF_SNIFF, default=False): cv.boolean,
            cv.Optional(CONF_GROUPS, default=[]): cv.ensure_list(GROUP_SCHEMA),
        }
    ),
    cv.only_on_esp32,
    cv.only_with_framework(cv.Framework.ESP_IDF),
)

# Action schemas for send_on, send_off, send_dim_plus, send_dim_minus
LITEWAVE_GROUP_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(LitewaveComponent),
        cv.Required(CONF_GROUP_ID): cv.use_id(LitewaveGroup),
    }
)

LITEWAVE_PROVISION_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(LitewaveComponent),
        cv.Required(CONF_GROUP_ID): cv.use_id(LitewaveGroup),
        cv.Required(CONF_LIGHT_INDEX): cv.int_range(min=0),
    }
)


async def _group_action_to_code(config, action_id, template_arg, args, action_class):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    group = await cg.get_variable(config[CONF_GROUP_ID])
    cg.add(var.set_group(group))
    return var


@automation.register_action(
    "litewave.send_on", LitewaveSendOnAction, LITEWAVE_GROUP_ACTION_SCHEMA
)
async def litewave_send_on_to_code(config, action_id, template_arg, args):
    return await _group_action_to_code(config, action_id, template_arg, args, LitewaveSendOnAction)


@automation.register_action(
    "litewave.send_off", LitewaveSendOffAction, LITEWAVE_GROUP_ACTION_SCHEMA
)
async def litewave_send_off_to_code(config, action_id, template_arg, args):
    return await _group_action_to_code(config, action_id, template_arg, args, LitewaveSendOffAction)


@automation.register_action(
    "litewave.send_dim_plus", LitewaveSendDimPlusAction, LITEWAVE_GROUP_ACTION_SCHEMA
)
async def litewave_send_dim_plus_to_code(config, action_id, template_arg, args):
    return await _group_action_to_code(config, action_id, template_arg, args, LitewaveSendDimPlusAction)


@automation.register_action(
    "litewave.send_dim_minus", LitewaveSendDimMinusAction, LITEWAVE_GROUP_ACTION_SCHEMA
)
async def litewave_send_dim_minus_to_code(config, action_id, template_arg, args):
    return await _group_action_to_code(config, action_id, template_arg, args, LitewaveSendDimMinusAction)


@automation.register_action(
    "litewave.provision_light", LitewaveProvisionLightAction, LITEWAVE_PROVISION_ACTION_SCHEMA
)
async def litewave_provision_light_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    group = await cg.get_variable(config[CONF_GROUP_ID])
    cg.add(var.set_group(group))
    cg.add(var.set_light_index(config[CONF_LIGHT_INDEX]))
    return var


def _hex_to_byte_array(hex_str, name):
    """Convert hex string to list of ints and generate a static array."""
    return [int(hex_str[i : i + 2], 16) for i in range(0, len(hex_str), 2)]


async def to_code(config):
    esp32.include_builtin_idf_component("ieee802154")
    esp32.add_idf_sdkconfig_option("CONFIG_IEEE802154_ENABLED", True)
    esp32.add_idf_sdkconfig_option("CONFIG_IEEE802154_RX_BUFFER_SIZE", 20)
    esp32.add_idf_sdkconfig_option("CONFIG_ESP_COEX_ENABLED", True)
    esp32.add_idf_sdkconfig_option("CONFIG_ESP_COEX_SW_COEXIST_ENABLE", True)
    # mbedTLS config for LTPDU v3 SRP-6a + AES-CCM provisioning
    esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_CCM_C", True)
    esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_MPI_MAX_SIZE", 512)

    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    cg.add(var.set_channel(config[CONF_CHANNEL]))
    cg.add(var.set_pan_id(config[CONF_PAN_ID]))
    if CONF_ADMIN_KEY in config:
        cg.add(var.set_admin_key(config[CONF_ADMIN_KEY]))
    cg.add(var.set_sniff(config[CONF_SNIFF]))

    for group_conf in config.get(CONF_GROUPS, []):
        group_id = group_conf[CONF_ID]

        # ON/OFF token arrays (required)
        on_token_bytes = _hex_to_byte_array(group_conf[CONF_ON_TOKEN], "on")
        off_token_bytes = _hex_to_byte_array(group_conf[CONF_OFF_TOKEN], "off")

        on_arr_name = f"{group_id.id}_on_tok"
        off_arr_name = f"{group_id.id}_off_tok"
        cg.add_global(cg.RawExpression(
            f"static const uint8_t {on_arr_name}[] = {{{', '.join(f'0x{b:02X}' for b in on_token_bytes)}}}"
        ))
        cg.add_global(cg.RawExpression(
            f"static const uint8_t {off_arr_name}[] = {{{', '.join(f'0x{b:02X}' for b in off_token_bytes)}}}"
        ))

        group_var = cg.new_Pvariable(group_id)
        cg.add(group_var.set_on_sequence(group_conf[CONF_ON_SEQUENCE]))
        cg.add(group_var.set_on_token(cg.RawExpression(on_arr_name)))
        cg.add(group_var.set_off_sequence(group_conf[CONF_OFF_SEQUENCE]))
        cg.add(group_var.set_off_token(cg.RawExpression(off_arr_name)))

        # DIM+ token (optional)
        if CONF_DIM_PLUS_SEQUENCE in group_conf and CONF_DIM_PLUS_TOKEN in group_conf:
            dp_bytes = _hex_to_byte_array(group_conf[CONF_DIM_PLUS_TOKEN], "dim_plus")
            dp_arr_name = f"{group_id.id}_dp_tok"
            cg.add_global(cg.RawExpression(
                f"static const uint8_t {dp_arr_name}[] = {{{', '.join(f'0x{b:02X}' for b in dp_bytes)}}}"
            ))
            cg.add(group_var.set_dim_plus_sequence(group_conf[CONF_DIM_PLUS_SEQUENCE]))
            cg.add(group_var.set_dim_plus_token(cg.RawExpression(dp_arr_name)))

        # DIM- token (optional)
        if CONF_DIM_MINUS_SEQUENCE in group_conf and CONF_DIM_MINUS_TOKEN in group_conf:
            dm_bytes = _hex_to_byte_array(group_conf[CONF_DIM_MINUS_TOKEN], "dim_minus")
            dm_arr_name = f"{group_id.id}_dm_tok"
            cg.add_global(cg.RawExpression(
                f"static const uint8_t {dm_arr_name}[] = {{{', '.join(f'0x{b:02X}' for b in dm_bytes)}}}"
            ))
            cg.add(group_var.set_dim_minus_sequence(group_conf[CONF_DIM_MINUS_SEQUENCE]))
            cg.add(group_var.set_dim_minus_token(cg.RawExpression(dm_arr_name)))

        # Shared secret (optional, for provisioning)
        if CONF_SHARED_SECRET in group_conf:
            ss_bytes = _hex_to_byte_array(group_conf[CONF_SHARED_SECRET], "ss")
            ss_arr_name = f"{group_id.id}_ss"
            cg.add_global(cg.RawExpression(
                f"static const uint8_t {ss_arr_name}[] = {{{', '.join(f'0x{b:02X}' for b in ss_bytes)}}}"
            ))
            cg.add(group_var.set_shared_secret(cg.RawExpression(ss_arr_name), len(ss_bytes)))

        # Switch EUI / ACL payload (optional, for provisioning)
        if CONF_SWITCH_EUI in group_conf:
            switch_eui_str = group_conf[CONF_SWITCH_EUI]
            acl_bytes = build_switch_acl_payload(switch_eui_str)
            acl_arr_name = f"{group_id.id}_acl"
            cg.add_global(cg.RawExpression(
                f"static const uint8_t {acl_arr_name}[] = {{{', '.join(f'0x{b:02X}' for b in acl_bytes)}}}"
            ))
            cg.add(group_var.set_acl_payload(cg.RawExpression(acl_arr_name), len(acl_bytes)))
            cg.add(group_var.set_switch_eui(switch_eui_str))

        # Lights (optional, for provisioning)
        for light_conf in group_conf.get(CONF_LIGHTS, []):
            light_id = light_conf.get(CONF_ID, "")
            light_name = light_conf.get(CONF_NAME, "")
            light_host = light_conf.get(CONF_HOST, "")
            pairing_code = light_conf[CONF_PAIRING_CODE]
            cg.add(cg.RawStatement(
                f'{group_var}->add_light({{"{light_id}", '
                f'"{light_name}", '
                f'"{light_host}", '
                f'"{pairing_code}"}});'
            ))

        cg.add(var.add_group(group_var))

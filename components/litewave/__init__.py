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
CONF_SNIFF = "sniff"
CONF_GROUPS = "groups"
CONF_GROUP_ID = "group"
CONF_ON_TOKEN = "on_token"
CONF_OFF_TOKEN = "off_token"

litewave_ns = cg.esphome_ns.namespace("litewave")
LitewaveComponent = litewave_ns.class_("LitewaveComponent", cg.Component)
LitewaveGroup = litewave_ns.struct("LitewaveGroup")
LitewaveSendOnAction = litewave_ns.class_("LitewaveSendOnAction", automation.Action)
LitewaveSendOffAction = litewave_ns.class_("LitewaveSendOffAction", automation.Action)


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


GROUP_SCHEMA = cv.Schema(
    {
        cv.Required(CONF_ID): cv.declare_id(LitewaveGroup),
        cv.Required(CONF_ON_TOKEN): validate_token,
        cv.Required(CONF_OFF_TOKEN): validate_token,
    }
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(LitewaveComponent),
            cv.Optional(CONF_CHANNEL, default=26): cv.int_range(min=11, max=26),
            cv.Optional(CONF_PAN_ID, default=0x3B71): cv.hex_uint16_t,
            cv.Optional(CONF_SNIFF, default=False): cv.boolean,
            cv.Optional(CONF_GROUPS, default=[]): cv.ensure_list(GROUP_SCHEMA),
        }
    ),
    cv.only_on_esp32,
    cv.only_with_framework(cv.Framework.ESP_IDF),
)

LITEWAVE_SEND_ON_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(LitewaveComponent),
        cv.Required(CONF_GROUP_ID): cv.use_id(LitewaveGroup),
    }
)

LITEWAVE_SEND_OFF_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(LitewaveComponent),
        cv.Required(CONF_GROUP_ID): cv.use_id(LitewaveGroup),
    }
)


@automation.register_action(
    "litewave.send_on", LitewaveSendOnAction, LITEWAVE_SEND_ON_ACTION_SCHEMA
)
async def litewave_send_on_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    group = await cg.get_variable(config[CONF_GROUP_ID])
    cg.add(var.set_group(group))
    return var


@automation.register_action(
    "litewave.send_off", LitewaveSendOffAction, LITEWAVE_SEND_OFF_ACTION_SCHEMA
)
async def litewave_send_off_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    group = await cg.get_variable(config[CONF_GROUP_ID])
    cg.add(var.set_group(group))
    return var


async def to_code(config):
    esp32.include_builtin_idf_component("ieee802154")
    esp32.add_idf_sdkconfig_option("CONFIG_IEEE802154_ENABLED", True)
    esp32.add_idf_sdkconfig_option("CONFIG_IEEE802154_RX_BUFFER_SIZE", 20)
    esp32.add_idf_sdkconfig_option("CONFIG_ESP_COEX_ENABLED", True)
    esp32.add_idf_sdkconfig_option("CONFIG_ESP_COEX_SW_COEXIST_ENABLE", True)

    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    cg.add(var.set_channel(config[CONF_CHANNEL]))
    cg.add(var.set_pan_id(config[CONF_PAN_ID]))
    cg.add(var.set_sniff(config[CONF_SNIFF]))

    for group_conf in config.get(CONF_GROUPS, []):
        group_id = group_conf[CONF_ID]
        on_token_bytes = [int(group_conf[CONF_ON_TOKEN][i : i + 2], 16) for i in range(0, 28, 2)]
        off_token_bytes = [int(group_conf[CONF_OFF_TOKEN][i : i + 2], 16) for i in range(0, 28, 2)]

        # Generate static arrays so we can pass pointers
        on_arr_name = f"{group_id.id}_on_tok"
        off_arr_name = f"{group_id.id}_off_tok"
        on_arr_literal = ", ".join(f"0x{b:02X}" for b in on_token_bytes)
        off_arr_literal = ", ".join(f"0x{b:02X}" for b in off_token_bytes)
        cg.add_global(cg.RawExpression(f"static const uint8_t {on_arr_name}[] = {{{on_arr_literal}}}"))
        cg.add_global(cg.RawExpression(f"static const uint8_t {off_arr_name}[] = {{{off_arr_literal}}}"))

        group_var = cg.new_Pvariable(group_id)
        cg.add(group_var.set_on_token(cg.RawExpression(on_arr_name)))
        cg.add(group_var.set_off_token(cg.RawExpression(off_arr_name)))

        cg.add(var.add_group(group_var))

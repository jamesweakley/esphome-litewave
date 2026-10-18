import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import automation
from esphome.components import esp32
from esphome.const import CONF_ID

CODEOWNERS = ["@jamesweakley"]
DEPENDENCIES = ["wifi"]

CONF_LIGHTS = "lights"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_UDP_PORT = "udp_port"
CONF_AUTH_TOKEN = "auth_token"
CONF_LIGHT_ID = "light_id"
CONF_RED = "red"
CONF_GREEN = "green"
CONF_BLUE = "blue"
CONF_WHITE = "white"
CONF_TRANSITION_MS = "transition_ms"

nanoleaf_wifi_ns = cg.esphome_ns.namespace("nanoleaf_wifi")
NanoleafWifiComponent = nanoleaf_wifi_ns.class_("NanoleafWifiComponent", cg.Component)
NanoleafWifiLight = nanoleaf_wifi_ns.struct("NanoleafWifiLight")

NanoleafProvisionAction = nanoleaf_wifi_ns.class_("NanoleafProvisionAction", automation.Action)
NanoleafEnableExtControlAction = nanoleaf_wifi_ns.class_("NanoleafEnableExtControlAction", automation.Action)
NanoleafSendOnAction = nanoleaf_wifi_ns.class_("NanoleafSendOnAction", automation.Action)
NanoleafSendOffAction = nanoleaf_wifi_ns.class_("NanoleafSendOffAction", automation.Action)
NanoleafSetColorAction = nanoleaf_wifi_ns.class_("NanoleafSetColorAction", automation.Action)

LIGHT_SCHEMA = cv.Schema(
    {
        cv.Required(CONF_ID): cv.string_strict,
        cv.Required(CONF_HOST): cv.string_strict,
        cv.Optional(CONF_PORT, default=12566): cv.port,
        cv.Optional(CONF_UDP_PORT, default=60222): cv.port,
        cv.Optional(CONF_AUTH_TOKEN, default=""): cv.string_strict,
    }
)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(NanoleafWifiComponent),
        cv.Required(CONF_LIGHTS): cv.ensure_list(LIGHT_SCHEMA),
    }
).extend(cv.COMPONENT_SCHEMA)

PROVISION_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(NanoleafWifiComponent),
        cv.Required(CONF_LIGHT_ID): cv.templatable(cv.string_strict),
        cv.Optional(CONF_AUTH_TOKEN): cv.templatable(cv.string_strict),
    }
)

ENABLE_EXTCONTROL_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(NanoleafWifiComponent),
        cv.Required(CONF_LIGHT_ID): cv.templatable(cv.string_strict),
        cv.Optional(CONF_AUTH_TOKEN): cv.templatable(cv.string_strict),
    }
)

SEND_ON_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(NanoleafWifiComponent),
        cv.Required(CONF_LIGHT_ID): cv.templatable(cv.string_strict),
        cv.Optional(CONF_RED, default=255): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Optional(CONF_GREEN, default=255): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Optional(CONF_BLUE, default=255): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Optional(CONF_WHITE, default=0): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Optional(CONF_TRANSITION_MS, default=100): cv.templatable(cv.positive_int),
    }
)

SEND_OFF_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(NanoleafWifiComponent),
        cv.Required(CONF_LIGHT_ID): cv.templatable(cv.string_strict),
        cv.Optional(CONF_TRANSITION_MS, default=100): cv.templatable(cv.positive_int),
    }
)

SET_COLOR_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(NanoleafWifiComponent),
        cv.Required(CONF_LIGHT_ID): cv.templatable(cv.string_strict),
        cv.Required(CONF_RED): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Required(CONF_GREEN): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Required(CONF_BLUE): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Optional(CONF_WHITE, default=0): cv.templatable(cv.int_range(min=0, max=255)),
        cv.Optional(CONF_TRANSITION_MS, default=100): cv.templatable(cv.positive_int),
    }
)


@automation.register_action(
    "nanoleaf_wifi.provision_light",
    NanoleafProvisionAction,
    PROVISION_ACTION_SCHEMA,
)
async def nanoleaf_provision_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    template_id = await cg.templatable(config[CONF_LIGHT_ID], args, cg.std_string)
    cg.add(var.set_light_id(template_id))
    if CONF_AUTH_TOKEN in config:
        template_token = await cg.templatable(config[CONF_AUTH_TOKEN], args, cg.std_string)
        cg.add(var.set_auth_token(template_token))
    return var


@automation.register_action(
    "nanoleaf_wifi.enable_extcontrol",
    NanoleafEnableExtControlAction,
    ENABLE_EXTCONTROL_ACTION_SCHEMA,
)
async def nanoleaf_enable_extcontrol_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    template_id = await cg.templatable(config[CONF_LIGHT_ID], args, cg.std_string)
    cg.add(var.set_light_id(template_id))
    if CONF_AUTH_TOKEN in config:
        template_token = await cg.templatable(config[CONF_AUTH_TOKEN], args, cg.std_string)
        cg.add(var.set_auth_token(template_token))
    return var


@automation.register_action(
    "nanoleaf_wifi.send_on",
    NanoleafSendOnAction,
    SEND_ON_ACTION_SCHEMA,
)
async def nanoleaf_send_on_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    template_id = await cg.templatable(config[CONF_LIGHT_ID], args, cg.std_string)
    cg.add(var.set_light_id(template_id))
    cg.add(var.set_red(await cg.templatable(config[CONF_RED], args, cg.uint8)))
    cg.add(var.set_green(await cg.templatable(config[CONF_GREEN], args, cg.uint8)))
    cg.add(var.set_blue(await cg.templatable(config[CONF_BLUE], args, cg.uint8)))
    cg.add(var.set_white(await cg.templatable(config[CONF_WHITE], args, cg.uint8)))
    cg.add(var.set_transition_ms(await cg.templatable(config[CONF_TRANSITION_MS], args, cg.uint32)))
    return var


@automation.register_action(
    "nanoleaf_wifi.send_off",
    NanoleafSendOffAction,
    SEND_OFF_ACTION_SCHEMA,
)
async def nanoleaf_send_off_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    template_id = await cg.templatable(config[CONF_LIGHT_ID], args, cg.std_string)
    cg.add(var.set_light_id(template_id))
    cg.add(var.set_transition_ms(await cg.templatable(config[CONF_TRANSITION_MS], args, cg.uint32)))
    return var


@automation.register_action(
    "nanoleaf_wifi.set_color",
    NanoleafSetColorAction,
    SET_COLOR_ACTION_SCHEMA,
)
async def nanoleaf_set_color_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    template_id = await cg.templatable(config[CONF_LIGHT_ID], args, cg.std_string)
    cg.add(var.set_light_id(template_id))
    cg.add(var.set_red(await cg.templatable(config[CONF_RED], args, cg.uint8)))
    cg.add(var.set_green(await cg.templatable(config[CONF_GREEN], args, cg.uint8)))
    cg.add(var.set_blue(await cg.templatable(config[CONF_BLUE], args, cg.uint8)))
    cg.add(var.set_white(await cg.templatable(config[CONF_WHITE], args, cg.uint8)))
    cg.add(var.set_transition_ms(await cg.templatable(config[CONF_TRANSITION_MS], args, cg.uint32)))
    return var


async def to_code(config):
    esp32.include_builtin_idf_component("mdns")
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    for light_conf in config.get(CONF_LIGHTS, []):
        cg.add(
            var.add_light(
                light_conf[CONF_ID],
                light_conf[CONF_HOST],
                light_conf[CONF_PORT],
                light_conf[CONF_UDP_PORT],
                light_conf[CONF_AUTH_TOKEN],
            )
        )

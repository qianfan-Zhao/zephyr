/*
 * Copyright (c) 2018 qianfan Zhao
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <misc/byteorder.h>
#include <init.h>
#include <zephyr.h>
#include <board.h>
#include <device.h>
#include <gpio.h>

#include <usb/usb_common.h>
#include <usb/usb_device.h>
#include <logging/sys_log.h>

#define USBIO_GETPORT					0x53
#define USBIO_SETPORT					0x54
#define USBIO_SETDIR					0x55
#define USBIO_SETBIT					0x56
#define USBIO_CLEARBIT					0x57

#define USBIO_DIR_OUT					0
#define USBIO_DIR_IN					1

struct usb_gpio {
	const char *port;
	int pin;
	int dir;
};

#define USB_GPIO(_port, _pin) {				\
	.port = _port,					\
	.pin = _pin,					\
	.dir = USBIO_DIR_IN,				\
}

/* only support 16 channels due to the protocol's limit */
#define MAX_GPIO_NUM					16

static struct usb_gpio extenders[MAX_GPIO_NUM + 1] = {
	#ifdef LED0_GPIO_CONTROLLER
		USB_GPIO(LED0_GPIO_CONTROLLER, LED0_GPIO_PIN),
	#elif defined LED0_GPIO_PORT
		USB_GPIO(LED0_GPIO_PORT, LED0_GPIO_PIN),
	#endif

	#ifdef SW0_GPIO_CONTROLLER
		USB_GPIO(SW0_GPIO_CONTROLLER, SW0_GPIO_PIN),
	#elif defined SW0_GPIO_NAME
		USB_GPIO(SW0_GPIO_NAME, SW0_GPIO_PIN),
	#endif

	/* add another gpios here ... */

	USB_GPIO(NULL, 0),	/* end */
};

#define u16_lsb(u)				(((u) >> 0) & 0xff)
#define u16_msb(u)				(((u) >> 8) & 0xff)
#define make_u16(lsb, msb)			((lsb) | ((msb) << 8))

#define foreach_usb_gpio(usbio, extender_table, gpio)			\
	for (								\
		usbio = &extender_table[0];				\
		gpio = device_get_binding(usbio->port),			\
		gpio && usbio->port;					\
		++usbio							\
	)

static int usbio_vendor_handler_req(struct usb_setup_packet *setup,
				    s32_t *transfer_len, u8_t **vendor_data)
{
	struct usb_gpio *usbio;
	struct device *gpio;
	u8_t *user_data;
	u16_t data;
	int i = 0;
	u32_t v;

	user_data = *vendor_data;
	data = make_u16(user_data[0], user_data[1]);

	switch (setup->bRequest) {
	case USBIO_GETPORT:
		data = 0;
		foreach_usb_gpio(usbio, extenders, gpio) {
			if (!gpio_pin_read(gpio, usbio->pin, &v))
				data |= (v << i);
			i++;
		}

		user_data[0] = u16_lsb(data); /* lsb */
		user_data[1] = u16_msb(data); /* msb */
		break;

	case USBIO_SETDIR:
		foreach_usb_gpio(usbio, extenders, gpio) {
			usbio->dir = data & 0x1;
			data >>= 1;

			if (usbio->dir == USBIO_DIR_OUT) {
				gpio_pin_configure(gpio, usbio->pin,
						   GPIO_DIR_OUT);
			} else {
				gpio_pin_configure(gpio, usbio->pin,
						   GPIO_DIR_IN);
			}
		}
		break;

	case USBIO_SETPORT:
		foreach_usb_gpio(usbio, extenders, gpio) {
			if (usbio->dir == GPIO_DIR_OUT) {
				gpio_pin_write(gpio, usbio->pin,
					       data & 0x1);
			}

			data >>= 1;
		}
		break;

	case USBIO_SETBIT:
		foreach_usb_gpio(usbio, extenders, gpio) {
			if ((usbio->dir == GPIO_DIR_OUT) && (data & 0x1)) {
				gpio_pin_write(gpio, usbio->pin, 1);
			}

			data >>= 1;
		}
		break;

	case USBIO_CLEARBIT:
		foreach_usb_gpio(usbio, extenders, gpio) {
			if ((usbio->dir == GPIO_DIR_OUT) && (data & 0x1)) {
				gpio_pin_write(gpio, usbio->pin, 0);
			}

			data >>= 1;
		}
		break;

	default:
		return -1;
	}

	return 0;
}

static u8_t usbio_descriptor[] = {
	/* Device Descriptor */
	0x12,						/* bLength */
	USB_DEVICE_DESC,				/* bDescriptorType */
	0x00, 0x02,					/* bcdUSB */
	0xff,						/* bDeviceClass, Vendor */
	0x00,						/* bDeviceSubClass */
	0x00,						/* bDeviceProtocol */
	MAX_PACKET_SIZE0,				/* bMaxPacketSize0 */
	u16_lsb(CONFIG_USB_DEVICE_VID),			/* idVendor */
	u16_msb(CONFIG_USB_DEVICE_VID),
	u16_lsb(CONFIG_USB_DEVICE_PID),			/* idProduct */
	u16_msb(CONFIG_USB_DEVICE_PID),
	u16_lsb(BCDDEVICE_RELNUM),			/* bcdDevice */
	u16_msb(BCDDEVICE_RELNUM),
	0x01,						/* iManufacturer */
	0x02,						/* iProduct */
	0x03,						/* iSerial */
	0x01,						/* bNumConfigurations */

	/* Configuration Descriptor */
	0x09,						/* bLength */
	USB_CONFIGURATION_DESC,				/* bDescriptorType */
	0x12, 0x00,					/* wTotalLength */
	0x01,						/* bNumInterfaces */
	0x01,						/* bConfigurationValue */
	0x00,						/* iConfiguration */
	0xa0,						/* bmAttributes */
	0x32,						/* bMaxPower */
	/* Interface Descriptor */
	0x09,						/* bLength */
	USB_INTERFACE_DESC,				/* bDescriptorType */
	0x00,						/* bInterfaceNumber */
	0x00,						/* bAlternateSetting */
	0x00,						/* bNumEndpoints */
	0xff,						/* bInterfaceClass, Vendor */
	0x00,						/* bInterfaceSubClass */
	0xff,						/* bInterfaceProtocol */
	0x00,						/* iInterface */

	/* Language String Descriptor */
	0x04,						/* bLength */
	USB_STRING_DESC,				/* bDescriptorType */
	0x09, 0x04,					/* wLANGID, English */

	/* MFR String Descriptor */
	14,						/* bLength */
	USB_STRING_DESC,				/* bDescriptorType */
	'z', 0x00, 'e', 0x00, 'p', 0x00, 'h', 0x00, 'y', 0x00, 'r', 0x00,

	/* Product String Descriptor */
	28,						/* bLength */
	USB_STRING_DESC,				/* bDescriptorType */
	'G', 0x00, 'P', 0x00, 'I', 0x00, 'O', 0x00, ' ', 0x00, 'e', 0x00,
	'x', 0x00, 't', 0x00, 'e', 0x00, 'n', 0x00, 'd', 0x00, 'e', 0x00,
	'r', 0x00,

	/* Serial String Descriptor */
	14,						/* bLength */
	USB_STRING_DESC,				/* bDescriptorType */
	'0', 0x00, '1', 0x00, '2', 0x00, '3', 0x00, '4', 0x00, '5', 0x00,

	/* Zephyr Terminal Descriptor */
	0x00,						/* bLength */
	0x00,						/* bDescriptorType */
};


/* USB gpio extender doesn't need another endpoint excepted EP0 */
static struct usb_cfg_data usbio_config = {
	.usb_device_description = usbio_descriptor,
	.interface = {
		.vendor_handler = usbio_vendor_handler_req,
	},
};

static int usbio_init(struct device *dev)
{
	static u8_t vendor_data[16];
	int ret = 0;

	usbio_config.interface.vendor_data = vendor_data;

	ret = usb_set_config(&usbio_config);
	if (ret < 0) {
		SYS_LOG_ERR("Failed to config USB");
		return ret;
	}

	ret = usb_enable(&usbio_config);
	if (ret < 0) {
		SYS_LOG_ERR("Failed to enable USB");
		return ret;
	}

	return ret;
}


SYS_INIT(usbio_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);

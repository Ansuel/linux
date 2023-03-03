// SPDX-License-Identifier: GPL-2.0
// Copyright 2017 Ben Whitten <ben.whitten@gmail.com>
// Copyright 2007 Oliver Jowett <oliver@opencloud.com>
//
// LED Kernel Netdev Trigger
//
// Toggles the LED to reflect the link and traffic state of a named net device
//
// Derived from ledtrig-timer.c which is:
//  Copyright 2005-2006 Openedhand Ltd.
//  Author: Richard Purdie <rpurdie@openedhand.com>

#include <linux/atomic.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include "../leds.h"

/*
 * Configurable sysfs attributes:
 *
 * device_name - network device name to monitor
 *               (not supported in hw mode)
 * interval - duration of LED blink, in milliseconds
 *            (not supported in hw mode)
 * link -  LED's normal state reflects whether the link is up
 *         (has carrier) or not
 * link_10 - LED's normal state reflects whether the link is
 *           up and at 10mbps speed (hardware only)
 * link_100 - LED's normal state reflects whether the link is
 *            up and at 100mbps speed (hardware only)
 * link_1000 - LED's normal state reflects whether the link is
 *             up and at 1000mbps speed (hardware only)
 * half_duplex - LED's normal state reflects whether the link is
 *               up and hafl duplex (hardware only)
 * full_duplex - LED's normal state reflects whether the link is
 *               up and full duplex (hardware only)
 * activity - LED's blinks on transmitted or received data (hardware only)
 * tx -  LED blinks on transmitted data
 * rx -  LED blinks on receive data
 * available_mode - Display available mode and how they can be handled
 *                  by the LED
 *
 */

struct led_netdev_data {
	enum led_blink_modes blink_mode;
	struct mutex lock;

	struct delayed_work work;
	struct notifier_block notifier;

	struct led_classdev *led_cdev;
	struct net_device *net_dev;

	char device_name[IFNAMSIZ];
	atomic_t interval;
	unsigned int last_activity;

	unsigned long mode;
	bool carrier_link_up;
};

struct netdev_led_attr_detail {
	char *name;
	bool hardware_only;
	enum led_trigger_netdev_modes bit;
};

static struct netdev_led_attr_detail attr_details[] = {
	{ .name = "link", .bit = TRIGGER_NETDEV_LINK},
	{ .name = "link_10", .hardware_only = true, .bit = TRIGGER_NETDEV_LINK_10},
	{ .name = "link_100", .hardware_only = true, .bit = TRIGGER_NETDEV_LINK_100},
	{ .name = "link_1000", .hardware_only = true, .bit = TRIGGER_NETDEV_LINK_1000},
	{ .name = "half_duplex", .hardware_only = true, .bit = TRIGGER_NETDEV_HALF_DUPLEX},
	{ .name = "full_duplex", .hardware_only = true, .bit = TRIGGER_NETDEV_FULL_DUPLEX},
	{ .name = "activity", .hardware_only = true, .bit = TRIGGER_NETDEV_ACTIVITY },
	{ .name = "tx", .bit = TRIGGER_NETDEV_TX},
	{ .name = "rx", .bit = TRIGGER_NETDEV_RX},
};

static bool validate_baseline_state(struct led_netdev_data *trigger_data)
{
	struct led_classdev *led_cdev = trigger_data->led_cdev;
	unsigned long hw_blink_modes = 0, sw_blink_modes = 0;
	struct netdev_led_attr_detail *detail;
	bool force_sw = false;
	int i;

	/* Check if we need to force sw mode for some feature */
	if (trigger_data->net_dev)
		force_sw = true;

	/* Hardware only controlled LED can't run in sw mode */
	if (force_sw && led_cdev->blink_mode == LED_BLINK_HW_CONTROLLED)
		return false;

	/* Check each attr and make sure they are all supported */
	for (i = 0; i < ARRAY_SIZE(attr_details); i++) {
		detail = &attr_details[i];

		/* Mode not active, skip */
		if (!test_bit(detail->bit, &trigger_data->mode))
			continue;

		/* Hardware only mode enabled on software controlled LED */
		if ((force_sw || led_cdev->blink_mode == LED_BLINK_SW_CONTROLLED) &&
		    detail->hardware_only)
			return false;

		/* Check if the mode supports hardware mode */
		if (led_cdev->blink_mode != LED_BLINK_SW_CONTROLLED) {
			/* Track modes that should be handled by sw */
			if (force_sw) {
				sw_blink_modes |= BIT(detail->bit);
				continue;
			}

			/* Check if single mode is present in the mask */
			if (BIT(detail->bit) & led_cdev->trigger_supported_flags_mask)
				hw_blink_modes |= BIT(detail->bit);
		} else {
			sw_blink_modes |= BIT(detail->bit);
		}
	}

	/* We can't run modes handled by both software and hardware. */
	if (hw_blink_modes && sw_blink_modes)
		return false;

	/* Return early if we are using software mode */
	if (sw_blink_modes) {
		trigger_data->blink_mode = LED_BLINK_SW_CONTROLLED;

		return true;
	}

	/* Make sure we support each requested mode */
	if (hw_blink_modes && hw_blink_modes != trigger_data->mode)
		return false;

	/* Check conflicts single rx or tx can't be active if activity is
	 * active.
	 */
	if (test_bit(TRIGGER_NETDEV_ACTIVITY, &hw_blink_modes) &&
	    (test_bit(TRIGGER_NETDEV_TX, &hw_blink_modes) ||
	     test_bit(TRIGGER_NETDEV_RX, &hw_blink_modes)))
		return false;

	/* Check conflicts single link speed can't be active if link is
	 * active.
	 */
	if (test_bit(TRIGGER_NETDEV_LINK, &hw_blink_modes) &&
	    (test_bit(TRIGGER_NETDEV_LINK_10, &hw_blink_modes) ||
	     test_bit(TRIGGER_NETDEV_LINK_100, &hw_blink_modes) ||
	     test_bit(TRIGGER_NETDEV_LINK_1000, &hw_blink_modes)))
		return false;

	/* Check if the full requested mode is supported */
	if (led_cdev->hw_control_is_supported(led_cdev, hw_blink_modes))
		return false;

	trigger_data->blink_mode = LED_BLINK_HW_CONTROLLED;

	return true;
}

static void set_baseline_state(struct led_netdev_data *trigger_data)
{
	int i;
	int current_brightness;
	struct netdev_led_attr_detail *detail;
	struct led_classdev *led_cdev = trigger_data->led_cdev;

	/* Modes already validated. Directly apply hw trigger modes */
	if (trigger_data->blink_mode == LED_BLINK_HW_CONTROLLED) {
		unsigned long flags = 0;

		for (i = 0; i < ARRAY_SIZE(attr_details); i++) {
			detail = &attr_details[i];

			if (!test_bit(detail->bit, &trigger_data->mode))
				continue;

			flags |= BIT(detail->bit);
		}

		led_cdev->hw_control_set(led_cdev, flags);

		return;
	}

	/* Handle trigger modes by software */
	current_brightness = led_cdev->brightness;
	if (current_brightness)
		led_cdev->blink_brightness = current_brightness;
	if (!led_cdev->blink_brightness)
		led_cdev->blink_brightness = led_cdev->max_brightness;

	if (!trigger_data->carrier_link_up) {
		led_set_brightness(led_cdev, LED_OFF);
	} else {
		if (test_bit(TRIGGER_NETDEV_LINK, &trigger_data->mode))
			led_set_brightness(led_cdev,
					   led_cdev->blink_brightness);
		else
			led_set_brightness(led_cdev, LED_OFF);

		/* If we are looking for RX/TX start periodically
		 * checking stats
		 */
		if (test_bit(TRIGGER_NETDEV_TX, &trigger_data->mode) ||
		    test_bit(TRIGGER_NETDEV_RX, &trigger_data->mode))
			schedule_delayed_work(&trigger_data->work, 0);
	}
}

static ssize_t device_name_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct led_netdev_data *trigger_data = led_trigger_get_drvdata(dev);
	ssize_t len;

	mutex_lock(&trigger_data->lock);
	len = sprintf(buf, "%s\n", trigger_data->device_name);
	mutex_unlock(&trigger_data->lock);

	return len;
}

static ssize_t device_name_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t size)
{
	struct led_netdev_data *trigger_data = led_trigger_get_drvdata(dev);
	char old_device_name[IFNAMSIZ];
	struct net_device *old_net;

	if (size >= IFNAMSIZ)
		return -EINVAL;

	cancel_delayed_work_sync(&trigger_data->work);

	mutex_lock(&trigger_data->lock);

	/* Backup old device name and save old net */
	old_net = trigger_data->net_dev;
	trigger_data->net_dev = NULL;
	memcpy(old_device_name, trigger_data->device_name, IFNAMSIZ);

	/* Set the new device name */
	memcpy(trigger_data->device_name, buf, size);
	trigger_data->device_name[size] = 0;
	if (size > 0 && trigger_data->device_name[size - 1] == '\n')
		trigger_data->device_name[size - 1] = 0;

	if (trigger_data->device_name[0] != 0)
		trigger_data->net_dev =
		    dev_get_by_name(&init_net, trigger_data->device_name);

	if (!validate_baseline_state(trigger_data)) {
		/* Restore old net_dev and device_name */
		dev_put(trigger_data->net_dev);

		/* Restore device settings */
		trigger_data->net_dev = old_net;
		memcpy(trigger_data->device_name, old_device_name, IFNAMSIZ);

		mutex_unlock(&trigger_data->lock);
		return -EINVAL;
	}

	/* Everything is ok. We can drop reference to the old net */
	dev_put(old_net);

	trigger_data->carrier_link_up = false;
	if (trigger_data->net_dev != NULL)
		trigger_data->carrier_link_up = netif_carrier_ok(trigger_data->net_dev);

	trigger_data->last_activity = 0;

	set_baseline_state(trigger_data);
	mutex_unlock(&trigger_data->lock);

	return size;
}

static DEVICE_ATTR_RW(device_name);

static ssize_t netdev_led_attr_show(struct device *dev, char *buf,
				    enum led_trigger_netdev_modes attr)
{
	struct led_netdev_data *trigger_data = led_trigger_get_drvdata(dev);
	int bit;

	switch (attr) {
	case TRIGGER_NETDEV_LINK:
	case TRIGGER_NETDEV_LINK_10:
	case TRIGGER_NETDEV_LINK_100:
	case TRIGGER_NETDEV_LINK_1000:
	case TRIGGER_NETDEV_HALF_DUPLEX:
	case TRIGGER_NETDEV_FULL_DUPLEX:
	case TRIGGER_NETDEV_ACTIVITY:
	case TRIGGER_NETDEV_TX:
	case TRIGGER_NETDEV_RX:
		bit = attr;
		break;
	default:
		return -EINVAL;
	}

	return sprintf(buf, "%u\n", test_bit(bit, &trigger_data->mode));
}

static ssize_t netdev_led_attr_store(struct device *dev, const char *buf,
				     size_t size, enum led_trigger_netdev_modes attr)
{
	struct led_netdev_data *trigger_data = led_trigger_get_drvdata(dev);
	unsigned long state, old_mode = trigger_data->mode;
	int ret;
	int bit;

	ret = kstrtoul(buf, 0, &state);
	if (ret)
		return ret;

	switch (attr) {
	case TRIGGER_NETDEV_LINK:
	case TRIGGER_NETDEV_LINK_10:
	case TRIGGER_NETDEV_LINK_100:
	case TRIGGER_NETDEV_LINK_1000:
	case TRIGGER_NETDEV_HALF_DUPLEX:
	case TRIGGER_NETDEV_FULL_DUPLEX:
	case TRIGGER_NETDEV_ACTIVITY:
	case TRIGGER_NETDEV_TX:
	case TRIGGER_NETDEV_RX:
		bit = attr;
		break;
	default:
		return -EINVAL;
	}

	cancel_delayed_work_sync(&trigger_data->work);

	if (state)
		set_bit(bit, &trigger_data->mode);
	else
		clear_bit(bit, &trigger_data->mode);

	if (!validate_baseline_state(trigger_data)) {
		/* Restore old mode on validation fail */
		trigger_data->mode = old_mode;
		return -EINVAL;
	}

	set_baseline_state(trigger_data);

	return size;
}

#define DEFINE_NETDEV_TRIGGER(trigger_name, trigger) \
	static ssize_t trigger_name##_show(struct device *dev, \
		struct device_attribute *attr, char *buf) \
	{ \
		return netdev_led_attr_show(dev, buf, trigger); \
	} \
	static ssize_t trigger_name##_store(struct device *dev, \
		struct device_attribute *attr, const char *buf, size_t size) \
	{ \
		return netdev_led_attr_store(dev, buf, size, trigger); \
	} \
	static DEVICE_ATTR_RW(trigger_name)

DEFINE_NETDEV_TRIGGER(link, TRIGGER_NETDEV_LINK);
DEFINE_NETDEV_TRIGGER(link_10, TRIGGER_NETDEV_LINK_10);
DEFINE_NETDEV_TRIGGER(link_100, TRIGGER_NETDEV_LINK_100);
DEFINE_NETDEV_TRIGGER(link_1000, TRIGGER_NETDEV_LINK_1000);
DEFINE_NETDEV_TRIGGER(half_duplex, TRIGGER_NETDEV_HALF_DUPLEX);
DEFINE_NETDEV_TRIGGER(full_duplex, TRIGGER_NETDEV_FULL_DUPLEX);
DEFINE_NETDEV_TRIGGER(activity, TRIGGER_NETDEV_ACTIVITY);
DEFINE_NETDEV_TRIGGER(tx, TRIGGER_NETDEV_TX);
DEFINE_NETDEV_TRIGGER(rx, TRIGGER_NETDEV_RX);

static ssize_t interval_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct led_netdev_data *trigger_data = led_trigger_get_drvdata(dev);

	return sprintf(buf, "%u\n",
		       jiffies_to_msecs(atomic_read(&trigger_data->interval)));
}

static ssize_t interval_store(struct device *dev,
			      struct device_attribute *attr, const char *buf,
			      size_t size)
{
	struct led_netdev_data *trigger_data = led_trigger_get_drvdata(dev);
	int old_interval = atomic_read(&trigger_data->interval);
	u32 old_mode = trigger_data->mode;
	unsigned long value;
	int ret;

	ret = kstrtoul(buf, 0, &value);
	if (ret)
		return ret;

	/* impose some basic bounds on the timer interval */
	if (value < 5 || value > 10000)
		return -EINVAL;

	/* With hw blink the blink interval is handled internally */
	if (trigger_data->blink_mode == LED_BLINK_HW_CONTROLLED)
		return -EINVAL;

	cancel_delayed_work_sync(&trigger_data->work);

	atomic_set(&trigger_data->interval, msecs_to_jiffies(value));

	if (!validate_baseline_state(trigger_data)) {
		/* Restore old interval on validation error */
		atomic_set(&trigger_data->interval, old_interval);
		trigger_data->mode = old_mode;
		return -EINVAL;
	}

	set_baseline_state(trigger_data);	/* resets timer */

	return size;
}

static DEVICE_ATTR_RW(interval);

static ssize_t available_mode_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct led_netdev_data *trigger_data = led_trigger_get_drvdata(dev);
	struct led_classdev *led_cdev = trigger_data->led_cdev;
	struct netdev_led_attr_detail *detail;
	bool support_hw_mode;
	int i, len = 0;

	for (i = 0; i < ARRAY_SIZE(attr_details); i++) {
		detail = &attr_details[i];
		support_hw_mode = led_cdev->trigger_supported_flags_mask &
				  BIT(detail->bit);

		len += sprintf(buf + len, "%s ", detail->name);

		if (detail->hardware_only) {
			if (trigger_data->net_dev || !support_hw_mode)
				len += sprintf(buf + len, "[unavailable]");
			else
				len += sprintf(buf + len, "[hardware]");
		} else {
			len += sprintf(buf + len, "[software]");

			if (support_hw_mode && !trigger_data->net_dev)
				len += sprintf(buf + len, "[hardware]");
		}

		if (test_bit(detail->bit, &trigger_data->mode))
			len += sprintf(buf + len, "[on]");

		len += sprintf(buf + len, "\n");
	}

	return len;
}

static DEVICE_ATTR_RO(available_mode);

static struct attribute *netdev_trig_attrs[] = {
	&dev_attr_device_name.attr,
	&dev_attr_link.attr,
	&dev_attr_link_10.attr,
	&dev_attr_link_100.attr,
	&dev_attr_link_1000.attr,
	&dev_attr_half_duplex.attr,
	&dev_attr_full_duplex.attr,
	&dev_attr_activity.attr,
	&dev_attr_rx.attr,
	&dev_attr_tx.attr,
	&dev_attr_interval.attr,
	&dev_attr_available_mode.attr,
	NULL
};
ATTRIBUTE_GROUPS(netdev_trig);

static int netdev_trig_notify(struct notifier_block *nb,
			      unsigned long evt, void *dv)
{
	struct net_device *dev =
		netdev_notifier_info_to_dev((struct netdev_notifier_info *)dv);
	struct led_netdev_data *trigger_data =
		container_of(nb, struct led_netdev_data, notifier);

	if (evt != NETDEV_UP && evt != NETDEV_DOWN && evt != NETDEV_CHANGE
	    && evt != NETDEV_REGISTER && evt != NETDEV_UNREGISTER
	    && evt != NETDEV_CHANGENAME)
		return NOTIFY_DONE;

	if (!(dev == trigger_data->net_dev ||
	      (evt == NETDEV_CHANGENAME && !strcmp(dev->name, trigger_data->device_name)) ||
	      (evt == NETDEV_REGISTER && !strcmp(dev->name, trigger_data->device_name))))
		return NOTIFY_DONE;

	cancel_delayed_work_sync(&trigger_data->work);

	mutex_lock(&trigger_data->lock);

	trigger_data->carrier_link_up = false;
	switch (evt) {
	case NETDEV_CHANGENAME:
	case NETDEV_REGISTER:
		if (trigger_data->net_dev)
			dev_put(trigger_data->net_dev);
		dev_hold(dev);
		trigger_data->net_dev = dev;
		break;
	case NETDEV_UNREGISTER:
		dev_put(trigger_data->net_dev);
		trigger_data->net_dev = NULL;
		break;
	case NETDEV_UP:
	case NETDEV_CHANGE:
		trigger_data->carrier_link_up = netif_carrier_ok(dev);
		break;
	}

	set_baseline_state(trigger_data);

	mutex_unlock(&trigger_data->lock);

	return NOTIFY_DONE;
}

/* here's the real work! */
static void netdev_trig_work(struct work_struct *work)
{
	struct led_netdev_data *trigger_data =
		container_of(work, struct led_netdev_data, work.work);
	struct rtnl_link_stats64 *dev_stats;
	unsigned int new_activity;
	struct rtnl_link_stats64 temp;
	unsigned long interval;
	int invert;

	/* If we dont have a device, insure we are off */
	if (!trigger_data->net_dev) {
		led_set_brightness(trigger_data->led_cdev, LED_OFF);
		return;
	}

	/* If we are not looking for RX/TX then return  */
	if (!test_bit(TRIGGER_NETDEV_TX, &trigger_data->mode) &&
	    !test_bit(TRIGGER_NETDEV_RX, &trigger_data->mode))
		return;

	dev_stats = dev_get_stats(trigger_data->net_dev, &temp);
	new_activity =
	    (test_bit(TRIGGER_NETDEV_TX, &trigger_data->mode) ?
		dev_stats->tx_packets : 0) +
	    (test_bit(TRIGGER_NETDEV_RX, &trigger_data->mode) ?
		dev_stats->rx_packets : 0);

	if (trigger_data->last_activity != new_activity) {
		led_stop_software_blink(trigger_data->led_cdev);

		invert = test_bit(TRIGGER_NETDEV_LINK, &trigger_data->mode);
		interval = jiffies_to_msecs(
				atomic_read(&trigger_data->interval));
		/* base state is ON (link present) */
		led_blink_set_oneshot(trigger_data->led_cdev,
				      &interval,
				      &interval,
				      invert);
		trigger_data->last_activity = new_activity;
	}

	schedule_delayed_work(&trigger_data->work,
			(atomic_read(&trigger_data->interval)*2));
}

static int netdev_trig_activate(struct led_classdev *led_cdev)
{
	struct led_netdev_data *trigger_data;
	int rc;

	trigger_data = kzalloc(sizeof(struct led_netdev_data), GFP_KERNEL);
	if (!trigger_data)
		return -ENOMEM;

	mutex_init(&trigger_data->lock);

	trigger_data->notifier.notifier_call = netdev_trig_notify;
	trigger_data->notifier.priority = 10;

	INIT_DELAYED_WORK(&trigger_data->work, netdev_trig_work);

	trigger_data->led_cdev = led_cdev;
	trigger_data->net_dev = NULL;
	trigger_data->device_name[0] = 0;

	trigger_data->mode = 0;
	atomic_set(&trigger_data->interval, msecs_to_jiffies(50));
	trigger_data->last_activity = 0;
	if (led_cdev->blink_mode != LED_BLINK_SW_CONTROLLED) {
		/* With hw mode supported, check what we have active */
		if (led_cdev->hw_control_get(led_cdev, &trigger_data->mode))
			trigger_data->blink_mode = LED_BLINK_HW_CONTROLLED;
	}

	led_set_trigger_data(led_cdev, trigger_data);

	rc = register_netdevice_notifier(&trigger_data->notifier);
	if (rc)
		kfree(trigger_data);

	return rc;
}

static void netdev_trig_deactivate(struct led_classdev *led_cdev)
{
	struct led_netdev_data *trigger_data = led_get_trigger_data(led_cdev);

	unregister_netdevice_notifier(&trigger_data->notifier);

	cancel_delayed_work_sync(&trigger_data->work);

	if (trigger_data->net_dev)
		dev_put(trigger_data->net_dev);

	kfree(trigger_data);
}

static struct led_trigger netdev_led_trigger = {
	.name = "netdev",
	.supported_blink_modes = LED_TRIGGER_SWHW,
	.activate = netdev_trig_activate,
	.deactivate = netdev_trig_deactivate,
	.groups = netdev_trig_groups,
};

static int __init netdev_trig_init(void)
{
	return led_trigger_register(&netdev_led_trigger);
}

static void __exit netdev_trig_exit(void)
{
	led_trigger_unregister(&netdev_led_trigger);
}

module_init(netdev_trig_init);
module_exit(netdev_trig_exit);

MODULE_AUTHOR("Ben Whitten <ben.whitten@gmail.com>");
MODULE_AUTHOR("Oliver Jowett <oliver@opencloud.com>");
MODULE_DESCRIPTION("Netdev LED trigger");
MODULE_LICENSE("GPL v2");

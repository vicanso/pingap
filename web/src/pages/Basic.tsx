import { LoadingPage } from "@/components/loading";
import useConfigState from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import { newZodBytes, newZodDuration, newZodNumber } from "@/helpers/util";
import useBasicState from "@/states/basic";
import { useShallow } from "zustand/react/shallow";

export default function Basic() {
  const basicI18n = useI18n("basic");
  const [basicInfo] = useBasicState(useShallow((state) => [state.data]));
  const [config, initialized, update] = useConfigState(
    useShallow((state) => [state.data, state.initialized, state.update]),
  );
  if (!initialized) {
    return <LoadingPage />;
  }
  const basic = config.basic;

  const items: ExFormItem[] = [
    {
      name: "name",
      label: basicI18n("name"),
      placeholder: basicI18n("namePlaceholder"),
      defaultValue: basic.name,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "threads",
      label: basicI18n("threads"),
      placeholder: basicI18n("threadsPlaceholder"),
      defaultValue: basic.threads,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "work_stealing",
      label: basicI18n("workStealing"),
      placeholder: "",
      defaultValue: basic.work_stealing || null,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "listener_tasks_per_fd",
      label: basicI18n("listenerTasksPerFd"),
      placeholder: basicI18n("listenerTasksPerFdPlaceholder"),
      defaultValue: basic.listener_tasks_per_fd,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "upstream_keepalive_pool_size",
      label: basicI18n("upstreamKeepalivePoolSize"),
      placeholder: basicI18n("upstreamKeepalivePoolSizePlaceholder"),
      defaultValue: basic.upstream_keepalive_pool_size,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "log_level",
      label: basicI18n("logLevel"),
      placeholder: basicI18n("logLevelPlaceholder"),
      defaultValue: basic.log_level,
      span: 3,
      category: ExFormItemCategory.SELECT,
      options: newStringOptions(
        ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"],
        false,
        true,
      ),
    },
    {
      name: "log_format_json",
      label: basicI18n("logFormatJson"),
      placeholder: "",
      defaultValue: basic.log_format_json,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "log_buffered_size",
      label: basicI18n("logBufferedSize"),
      placeholder: basicI18n("logBufferedSizePlaceholder"),
      defaultValue: basic.log_buffered_size,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "grace_period",
      label: basicI18n("gracePeriod"),
      placeholder: basicI18n("gracePeriodPlaceholder"),
      defaultValue: basic.grace_period,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "graceful_shutdown_timeout",
      label: basicI18n("gracefulShutdownTimeout"),
      placeholder: basicI18n("gracefulShutdownTimeoutPlaceholder"),
      defaultValue: basic.graceful_shutdown_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "auto_restart_check_interval",
      label: basicI18n("autoRestartCheckInterval"),
      placeholder: basicI18n("autoRestartCheckIntervalPlaceholder"),
      defaultValue: basic.auto_restart_check_interval,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "pid_file",
      label: basicI18n("pidFile"),
      placeholder: basicI18n("pidFilePlaceholder"),
      defaultValue: basic.pid_file,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "cache_directory",
      label: basicI18n("cacheDirectory"),
      placeholder: basicI18n("cacheDirectoryPlaceholder"),
      defaultValue: basic.cache_directory,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "cache_max_size",
      label: basicI18n("cacheMaxSize"),
      placeholder: basicI18n("cacheMaxSizePlaceholder"),
      defaultValue: basic.cache_max_size,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "upgrade_sock",
      label: basicI18n("upgradeSock"),
      placeholder: basicI18n("upgradeSockPlaceholder"),
      defaultValue: basic.upgrade_sock,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "user",
      label: basicI18n("user"),
      placeholder: basicI18n("userPlaceholder"),
      defaultValue: basic.user,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "group",
      label: basicI18n("group"),
      placeholder: basicI18n("groupPlaceholder"),
      defaultValue: basic.group,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "webhook_type",
      label: basicI18n("webhookType"),
      placeholder: basicI18n("webhookTypePlaceholder"),
      defaultValue: basic.webhook_type,
      span: 3,
      category: ExFormItemCategory.SELECT,
      options: newStringOptions(["normal", "wecom", "dingtalk"], true),
    },
    {
      name: "webhook_notifications",
      label: basicI18n("webhookNotifications"),
      placeholder: basicI18n("webhookNotificationsPlaceholder"),
      defaultValue: basic.webhook_notifications,
      span: 3,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(
        [
          "backend_status",
          "lets_encrypt",
          "diff_config",
          "restart",
          "restart_fail",
          "reload_config",
          "reload_config_fail",
          "tls_validity",
          "parse_certificate_fail",
          "service_discover_fail",
          "upstream_status",
        ].sort(),
        true,
      ),
    },
    {
      name: "webhook",
      label: basicI18n("webhook"),
      placeholder: basicI18n("webhookPlaceholder"),
      defaultValue: basic.webhook,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
  ];
  if (basicInfo.features.includes("tracing")) {
    items.push({
      name: "sentry",
      label: basicI18n("sentry"),
      placeholder: basicI18n("sentryPlaceholder"),
      defaultValue: basic.sentry,
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }
  if (basicInfo.features.includes("pyroscope")) {
    items.push({
      name: "pyroscope",
      label: basicI18n("pyroscope"),
      placeholder: basicI18n("pyroscopePlaceholder"),
      defaultValue: basic.pyroscope,
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  items.push({
    name: "error_template",
    label: basicI18n("errorTemplate"),
    placeholder: basicI18n("errorTemplatePlaceholder"),
    defaultValue: basic.error_template,
    span: 6,
    rows: 8,
    category: ExFormItemCategory.TEXTAREA,
  });

  const schema = z.object({
    name: z.string().optional(),
    threads: newZodNumber().optional(),
    log_level: z.string().optional().or(z.null()),
    log_buffered_size: newZodBytes().optional(),
    grace_period: newZodDuration().optional(),
    graceful_shutdown_timeout: newZodDuration().optional(),
    auto_restart_check_interval: newZodDuration().optional(),
    cache_max_size: newZodBytes().optional(),
  });
  return (
    <div className="grow overflow-auto p-4">
      <ExForm
        category="basic"
        items={items}
        schema={schema}
        defaultShow={9}
        onSave={async (value) => update("pingap", "basic", value)}
      />
    </div>
  );
}

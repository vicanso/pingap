import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";
import { LoadingPage } from "@/components/loading";
import useConfigState from "@/states/config";
import {
  ExForm,
  ExFormItem,
  ExFormItemCategory,
  getBooleanOptions,
  getStringOptions,
} from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";

export default function Basic() {
  const basicI18n = useI18n("basic");
  const [config, initialized, update] = useConfigState((state) => [
    state.data,
    state.initialized,
    state.update,
  ]);
  if (!initialized) {
    return <LoadingPage />;
  }
  const basic = config.basic;

  const items: ExFormItem[] = [
    {
      name: "name",
      label: basicI18n("name"),
      placehodler: basicI18n("namePlaceholder"),
      defaultValue: basic.name,
      span: 4,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "threads",
      label: basicI18n("threads"),
      placehodler: basicI18n("threadsPlaceholder"),
      defaultValue: basic.threads,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "work_stealing",
      label: basicI18n("workStealing"),
      placehodler: "",
      defaultValue: basic.work_stealing || null,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: getBooleanOptions(),
    },
    {
      name: "log_level",
      label: basicI18n("logLevel"),
      placehodler: basicI18n("logLevelPlaceholder"),
      defaultValue: basic.log_level,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "log_format_json",
      label: basicI18n("logFormatJson"),
      placehodler: "",
      defaultValue: basic.log_format_json,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: getBooleanOptions(),
    },
    {
      name: "log_buffered_size",
      label: basicI18n("logBufferedSize"),
      placehodler: basicI18n("logBufferedSizePlaceholder"),
      defaultValue: basic.log_buffered_size,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "grace_period",
      label: basicI18n("gracePeriod"),
      placehodler: basicI18n("gracePeriodPlaceholder"),
      defaultValue: basic.grace_period,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "graceful_shutdown_timeout",
      label: basicI18n("gracefulShutdownTimeout"),
      placehodler: basicI18n("gracefulShutdownTimeoutPlaceholder"),
      defaultValue: basic.graceful_shutdown_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "auto_restart_check_interval",
      label: basicI18n("autoRestartCheckInterval"),
      placehodler: basicI18n("autoRestartCheckIntervalPlaceholder"),
      defaultValue: basic.auto_restart_check_interval,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "pid_file",
      label: basicI18n("pidFile"),
      placehodler: basicI18n("pidFilePlaceholder"),
      defaultValue: basic.pid_file,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "cache_directory",
      label: basicI18n("cacheDirectory"),
      placehodler: basicI18n("cacheDirectoryPlaceholder"),
      defaultValue: basic.cache_directory,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "cache_max_size",
      label: basicI18n("cacheMaxSize"),
      placehodler: basicI18n("cacheMaxSizePlaceholder"),
      defaultValue: basic.cache_max_size,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "upgrade_sock",
      label: basicI18n("upgradeSock"),
      placehodler: basicI18n("upgradeSockPlaceholder"),
      defaultValue: basic.upgrade_sock,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "user",
      label: basicI18n("user"),
      placehodler: basicI18n("userPlaceholder"),
      defaultValue: basic.user,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "group",
      label: basicI18n("group"),
      placehodler: basicI18n("groupPlaceholder"),
      defaultValue: basic.group,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "webhook_type",
      label: basicI18n("webhookType"),
      placehodler: basicI18n("webhookTypePlaceholder"),
      defaultValue: basic.webhook_type,
      span: 2,
      category: ExFormItemCategory.SELECT,
      options: getStringOptions(["normal", "wecom", "dingtalk"]),
    },
    {
      name: "webhook_notifications",
      label: basicI18n("webhookNotifications"),
      placehodler: basicI18n("webhookNotificationsPlaceholder"),
      defaultValue: basic.webhook_notifications,
      span: 2,
      category: ExFormItemCategory.MULTI_SELECT,
      options: getStringOptions(
        [
          "backend_status",
          "lets_encrypt",
          "diff_config",
          "restart",
          "restart_fail",
          "reload_config",
          "reload_config_fail",
          "tls_validity",
          "service_discover_fail",
        ].sort(),
      ),
    },
    {
      name: "webhook",
      label: basicI18n("webhook"),
      placehodler: basicI18n("webhookPlaceholder"),
      defaultValue: basic.webhook,
      span: 4,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "sentry",
      label: basicI18n("sentry"),
      placehodler: basicI18n("sentryPlaceholder"),
      defaultValue: basic.sentry,
      span: 4,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "pyroscope",
      label: basicI18n("pyroscope"),
      placehodler: basicI18n("pyroscopePlaceholder"),
      defaultValue: basic.pyroscope,
      span: 4,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "error_template",
      label: basicI18n("errorTemplate"),
      placehodler: basicI18n("errorTemplatePlaceholder"),
      defaultValue: basic.error_template,
      span: 4,
      rows: 8,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];
  const schema = z.object({
    threads: z.string().optional(),
  });
  return (
    <>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          <ExForm
            items={items}
            schema={schema}
            defaultShow={9}
            onSave={async (value) => update("pingap", "basic", value)}
          />
        </div>
      </div>
    </>
  );
}

import { useTranslation } from "react-i18next";
import useConfigStore from "../states/config";
import Loading from "../components/loading";
import FormEditor from "../components/form-editor";
import { FormItem, FormItemCategory } from "../components/form-common";

export default function BasicInfo() {
  const { t } = useTranslation();

  const [initialized, config, update] = useConfigStore((state) => [
    state.initialized,
    state.data,
    state.update,
  ]);
  if (!initialized) {
    return <Loading />;
  }
  const basic = config.basic;
  const arr: FormItem[] = [
    {
      id: "name",
      label: t("basic.name"),
      defaultValue: basic.name,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "pid_file",
      label: t("basic.pidFile"),
      defaultValue: basic.pid_file,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upgrade_sock",
      label: t("basic.upgradeSock"),
      defaultValue: basic.upgrade_sock,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "threads",
      label: t("basic.threads"),
      defaultValue: basic.threads,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "work_stealing",
      label: t("basic.workStealing"),
      defaultValue: basic.work_stealing,
      span: 6,
      category: FormItemCategory.CHECKBOX,
      options: [
        {
          label: "Yes",
          option: 1,
          value: true,
        },
        {
          label: "No",
          option: 0,
          value: false,
        },
        {
          label: "None",
          option: -1,
          value: null,
        },
      ],
    },
    {
      id: "user",
      label: t("basic.user"),
      defaultValue: basic.user,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "group",
      label: t("basic.group"),
      defaultValue: basic.group,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "grace_period",
      label: t("basic.gracePeriod"),
      defaultValue: basic.grace_period,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "graceful_shutdown_timeout",
      label: t("basic.gracefulShutdownTimeout"),
      defaultValue: basic.graceful_shutdown_timeout,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "log_level",
      label: t("basic.logLevel"),
      defaultValue: basic.log_level,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "log_capacity",
      label: t("basic.logCapacity"),
      defaultValue: basic.log_capacity,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upstream_keepalive_pool_size",
      label: t("basic.upstreamKeepalivePoolSize"),
      defaultValue: basic.upstream_keepalive_pool_size,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "auto_restart_check_interval",
      label: t("basic.autoRestartCheckInterval"),
      defaultValue: basic.auto_restart_check_interval,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "cache_max_size",
      label: t("basic.cacheMaxSize"),
      defaultValue: basic.cache_max_size,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "certificate_file",
      label: t("basic.certificateFile"),
      defaultValue: basic.certificate_file,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "webhook_type",
      label: t("basic.webhookType"),
      defaultValue: basic.webhook_type,
      span: 6,
      category: FormItemCategory.WEBHOOK_TYPE,
      options: ["normal", "wecom", "dingtalk"],
    },
    {
      id: "webhook_notifications",
      label: t("basic.webhookNotifications"),
      defaultValue: basic.webhook_notifications,
      span: 6,
      category: FormItemCategory.WEBHOOK_NOTIFICATIONS,
      options: [
        "backend_unhealthy",
        "lets_encrypt",
        "diff_config",
        "restart",
        "restart_fail",
        "tls_validity",
      ],
    },
    {
      id: "webhook",
      label: t("basic.webhook"),
      defaultValue: basic.webhook,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "sentry",
      label: t("basic.sentry"),
      defaultValue: basic.sentry,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "pyroscope",
      label: t("basic.pyroscope"),
      defaultValue: basic.pyroscope,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "error_template",
      label: t("basic.errorTemplate"),
      defaultValue: basic.error_template,
      span: 12,
      minRows: 8,
      category: FormItemCategory.TEXTAREA,
    },
  ];
  const onUpsert = async (name: string, data: Record<string, unknown>) => {
    return update("pingap", "basic", data);
  };
  return (
    <FormEditor
      title={t("basic.title")}
      description={t("basic.description")}
      items={arr}
      onUpsert={onUpsert}
    />
  );
}

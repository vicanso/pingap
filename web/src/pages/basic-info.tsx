import { useTranslation } from "react-i18next";
import useConfigStore from "../states/config";
import Loading from "../components/loading";
import FormEditor, {
  FormItem,
  FormItemCategory,
} from "../components/form-editor";

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
  const arr: FormItem[] = [
    {
      id: "name",
      label: t("basic.name"),
      defaultValue: config.name,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "pid_file",
      label: t("basic.pidFile"),
      defaultValue: config.pid_file,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upgrade_sock",
      label: t("basic.upgradeSock"),
      defaultValue: config.upgrade_sock,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "threads",
      label: t("basic.threads"),
      defaultValue: config.threads,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "work_stealing",
      label: t("basic.workStealing"),
      defaultValue: config.work_stealing,
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
      defaultValue: config.user,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "group",
      label: t("basic.group"),
      defaultValue: config.group,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "grace_period",
      label: t("basic.gracePeriod"),
      defaultValue: config.grace_period,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "graceful_shutdown_timeout",
      label: t("basic.gracefulShutdownTimeout"),
      defaultValue: config.graceful_shutdown_timeout,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "log_level",
      label: t("basic.logLevel"),
      defaultValue: config.log_level,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upstream_keepalive_pool_size",
      label: t("basic.upstreamKeepalivePoolSize"),
      defaultValue: config.upstream_keepalive_pool_size,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "webhook_type",
      label: t("basic.webhookType"),
      defaultValue: config.webhook_type,
      span: 4,
      category: FormItemCategory.WEBHOOK_TYPE,
      options: ["normal", "wecom", "dingtalk"],
    },
    {
      id: "webhook",
      label: t("basic.webhook"),
      defaultValue: config.webhook,
      span: 8,
      category: FormItemCategory.TEXT,
    },
    {
      id: "sentry",
      label: t("basic.sentry"),
      defaultValue: config.sentry,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "pyroscope",
      label: t("basic.pyroscope"),
      defaultValue: config.pyroscope,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "error_template",
      label: t("basic.errorTemplate"),
      defaultValue: config.error_template,
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

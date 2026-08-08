import { LoadingPage } from "@/components/loading";
import { useI18n } from "@/i18n";
import useConfigState, { Certificate } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import { omitEmptyArrayString } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import { ConfigEntityList, EntityText } from "@/components/config-entity-list";
import { CERTIFICATES } from "@/routers";
import { Check } from "lucide-react";

function getCertificateConfig(
  name: string,
  certificates?: Record<string, Certificate>,
) {
  if (!certificates) {
    return {} as Certificate;
  }
  return (certificates[name] || {}) as Certificate;
}

export default function Certificates() {
  const certificateI18n = useI18n("certificate");
  const i18n = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove, version] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.update,
      state.remove,
      state.version,
    ]),
  );
  const newCertificate = "*";
  const certificates = Object.keys(config.certificates || {});
  certificates.sort();
  // No `name` in the url means the category overview, `*` means the create form.
  const currentCertificate = searchParams.get("name") || "";

  if (!initialized) {
    return <LoadingPage />;
  }

  if (!currentCertificate) {
    return (
      <ConfigEntityList<Certificate>
        title={certificateI18n("title")}
        summary={certificateI18n("summary", { count: certificates.length })}
        nameLabel={certificateI18n("name")}
        addLabel={certificateI18n("add")}
        emptyText={certificateI18n("empty")}
        basePath={CERTIFICATES}
        newValue={newCertificate}
        names={certificates}
        values={config.certificates || {}}
        columns={[
          {
            key: "domains",
            label: certificateI18n("domains"),
            render: (value) => <EntityText value={value?.domains} />,
          },
          {
            key: "acme",
            label: certificateI18n("acme"),
            render: (value) => <EntityText value={value?.acme} />,
          },
          {
            key: "isDefault",
            label: certificateI18n("isDefault"),
            render: (value) =>
              value?.is_default ? (
                <Check className="size-4 text-primary" />
              ) : (
                <EntityText />
              ),
          },
        ]}
      />
    );
  }

  const handleSelectCertificate = (name: string) => {
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const certificateConfig = getCertificateConfig(
    currentCertificate,
    config.certificates,
  );
  const countLines = (value: string) => {
    const count = value.split("\n").length;
    return Math.min(Math.max(3, count), 8);
  };

  const items: ExFormItem[] = [
    {
      name: "tls_cert",
      label: certificateI18n("tlsCert"),
      placeholder: certificateI18n("tlsCertPlaceholder"),
      defaultValue: certificateConfig.tls_cert,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
      rows: countLines(certificateConfig.tls_cert || ""),
      nullAsEmpty: true,
    },
    {
      name: "tls_key",
      label: certificateI18n("tlsKey"),
      placeholder: certificateI18n("tlsKeyPlaceholder"),
      defaultValue: certificateConfig.tls_key,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
      rows: countLines(certificateConfig.tls_key || ""),
      nullAsEmpty: true,
    },
    {
      name: "domains",
      label: certificateI18n("domains"),
      placeholder: certificateI18n("domainsPlaceholder"),
      defaultValue: certificateConfig.domains,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "acme",
      label: certificateI18n("acme"),
      placeholder: "",
      defaultValue: certificateConfig.acme,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["lets_encrypt"], true, true),
    },
    {
      name: "is_default",
      label: certificateI18n("isDefault"),
      placeholder: "",
      defaultValue: certificateConfig.is_default,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "dns_challenge",
      label: certificateI18n("dnsChallenge"),
      placeholder: "",
      defaultValue: certificateConfig.dns_challenge,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "dns_provider",
      label: certificateI18n("dnsProvider"),
      placeholder: "",
      defaultValue: certificateConfig.dns_provider || "manual",
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(
        ["manual", "ali", "cf", "huawei", "tencent"],
        true,
        false,
      ),
    },
    {
      name: "dns_service_url",
      label: certificateI18n("dnsServiceUrl"),
      placeholder: certificateI18n("dnsServiceUrlPlaceholder"),
      defaultValue: certificateConfig.dns_service_url,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "is_ca",
      label: certificateI18n("isCa"),
      placeholder: "",
      defaultValue: certificateConfig.is_ca,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "buffer_days",
      label: certificateI18n("bufferDays"),
      placeholder: certificateI18n("bufferDaysPlaceholder"),
      defaultValue: certificateConfig.buffer_days,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
  ];

  let defaultShow = 2;
  if (currentCertificate === newCertificate) {
    defaultShow++;
    items.unshift({
      name: "name",
      label: certificateI18n("name"),
      placeholder: certificateI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }
  const schema = z.object({});
  const onRemove = async () => {
    return remove("certificate", currentCertificate).then(() => {
      backToList();
    });
  };

  return (
    <PageShell
      title={certificateI18n("title")}
      description={certificateI18n("description")}
      width="narrow"
      backTo={CERTIFICATES}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge
          name={currentCertificate}
          isNew={currentCertificate === newCertificate}
        />
      }
      actions={
        currentCertificate !== newCertificate ? (
          <History
            category="certificate"
            name={currentCertificate}
            onRestore={async (data) => {
              await update("certificate", currentCertificate, data);
            }}
          />
        ) : undefined
      }
    >
      <ExForm
        category="certificate"
        key={`${currentCertificate}-${version}`}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={currentCertificate === newCertificate ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentCertificate;
          if (name === newCertificate) {
            name = value["name"] as string;
          }
          omitEmptyArrayString(value);
          await update("certificate", name, value);
          handleSelectCertificate(name);
        }}
      />
    </PageShell>
  );
}

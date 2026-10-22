"use client";

import { SparklesIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import type { DefenseScenario } from "@/lib/purple-api";

type ScenarioStage = DefenseScenario["stages"][number];

export function FindingDefenseScenarioPanel({
  scenario,
  error,
  readOnly,
  busy,
  generating,
  draftDirty,
  onGenerate,
  onApplyStage,
}: {
  scenario: DefenseScenario | null;
  error: string;
  readOnly: boolean;
  busy: boolean;
  generating: boolean;
  draftDirty: boolean;
  onGenerate: () => void;
  onApplyStage: (stage: ScenarioStage) => void;
}) {
  const t = useTranslations("purple.scenario");
  const current = scenario?.state === "current";

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle>{t("title")}</CardTitle>
          {scenario ? (
            <Badge variant={current ? "secondary" : "destructive"}>{t(current ? "current" : "stale")}</Badge>
          ) : null}
        </div>
        <CardDescription>{t("description")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <p className="text-muted-foreground text-xs">{t("costNotice")}</p>
        {!readOnly && (!scenario || !current) ? (
          <div className="flex flex-wrap items-center gap-3">
            <Button type="button" disabled={busy || draftDirty} onClick={onGenerate}>
              {generating ? <Spinner /> : <SparklesIcon />}
              {t(scenario ? "regenerate" : "generate")}
            </Button>
            {draftDirty ? <span className="text-muted-foreground text-xs">{t("saveDraftFirst")}</span> : null}
          </div>
        ) : null}
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {!scenario ? <p className="text-muted-foreground text-sm">{t("empty")}</p> : null}
        {scenario ? (
          <>
            {scenario.state === "stale" ? (
              <Alert>
                <AlertDescription>{t("staleHelp")}</AlertDescription>
              </Alert>
            ) : null}
            <div className="space-y-3">
              <h3 className="font-semibold text-sm">{t("attackTitle")}</h3>
              <p className="text-sm">{scenario.title}</p>
              <ol className="space-y-3">
                {scenario.attack_steps.map((step, index) => (
                  <li key={step.id} className="rounded-md border p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-sm">{t("step", { n: index + 1 })}</span>
                      <Badge variant={step.basis === "observed" ? "secondary" : "outline"}>
                        {t(`basis.${step.basis}`)}
                      </Badge>
                    </div>
                    <p className="mt-2 whitespace-pre-wrap text-sm">{step.description}</p>
                    {step.evidence ? (
                      <p className="mt-2 whitespace-pre-wrap text-muted-foreground text-xs">
                        {t("evidence")}: {step.evidence}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ol>
            </div>
            <div className="space-y-3">
              <h3 className="font-semibold text-sm">{t("detectionTitle")}</h3>
              <Accordion key={scenario.id} type="multiple" defaultValue={[]} className="gap-2">
                {scenario.stages.map((stage, index) => {
                  const attackStep = scenario.attack_steps.find((step) => step.id === stage.attack_step_id);
                  return (
                    <AccordionItem
                      key={stage.id}
                      value={stage.id}
                      className="overflow-hidden rounded-lg border bg-card"
                    >
                      <AccordionTrigger className="px-4 py-3 hover:no-underline">
                        <span className="flex min-w-0 flex-1 flex-col gap-1.5">
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="font-medium leading-snug">
                              {t("stage", { n: index + 1 })}: {stage.title}
                            </span>
                            {attackStep ? <Badge variant="outline">{t(`basis.${attackStep.basis}`)}</Badge> : null}
                          </span>
                          <span className="font-normal text-muted-foreground text-xs">
                            {t("stageSummary", { equipment: stage.equipment.length, logs: stage.log_sources.length })}
                          </span>
                        </span>
                      </AccordionTrigger>
                      <AccordionContent className="space-y-4 border-t px-4 pt-4 pb-4">
                        {attackStep ? (
                          <p className="text-muted-foreground text-xs">
                            {t("linkedAttack")}: {attackStep.description}
                          </p>
                        ) : null}
                        <div className="space-y-2">
                          <h5 className="font-medium text-sm">{t("equipmentTitle")}</h5>
                          <p className="text-muted-foreground text-xs">{t("equipmentHelp")}</p>
                          {stage.equipment.length ? (
                            <ul className="space-y-2">
                              {stage.equipment.map((equipment) => (
                                <li
                                  key={`${stage.id}-equipment-${equipment.kind}-${equipment.presence}-${equipment.basis}`}
                                  className="flex flex-wrap items-start gap-2 text-sm"
                                >
                                  <span className="font-medium">{equipment.kind}</span>
                                  <Badge variant={equipment.presence === "absent" ? "destructive" : "outline"}>
                                    {t(`presence.${equipment.presence}`)}
                                  </Badge>
                                  {equipment.basis ? (
                                    <span className="text-muted-foreground">{equipment.basis}</span>
                                  ) : null}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-muted-foreground text-sm">{t("noEquipment")}</p>
                          )}
                        </div>
                        <div className="grid gap-4 sm:grid-cols-2">
                          <div>
                            <h5 className="font-medium text-sm">{t("logsTitle")}</h5>
                            {stage.log_sources.length ? (
                              <ul className="mt-1 list-disc pl-5 text-sm">
                                {stage.log_sources.map((source) => (
                                  <li key={`${stage.id}-log-${source}`}>{source}</li>
                                ))}
                              </ul>
                            ) : (
                              <p className="mt-1 text-sm">{t("unknown")}</p>
                            )}
                          </div>
                          <div>
                            <h5 className="font-medium text-sm">{t("fieldsTitle")}</h5>
                            <p className="mt-1 text-sm">{stage.required_fields.join(", ") || t("unknown")}</p>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <h5 className="font-medium text-sm">{t("ruleTitle")}</h5>
                          <p className="text-muted-foreground text-xs">{t("ruleHelp")}</p>
                          <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 font-mono text-xs">
                            {stage.rule_draft.query || t("noRule")}
                          </pre>
                          {stage.rule_draft.rationale ? (
                            <p className="whitespace-pre-wrap text-muted-foreground text-xs">
                              {stage.rule_draft.rationale}
                            </p>
                          ) : null}
                        </div>
                        <div className="grid gap-4 sm:grid-cols-2">
                          <div>
                            <h5 className="font-medium text-sm">{t("baselineTitle")}</h5>
                            <p className="mt-1 whitespace-pre-wrap text-sm">{stage.benign_baseline || t("unknown")}</p>
                          </div>
                          <div>
                            <h5 className="font-medium text-sm">{t("criteriaTitle")}</h5>
                            <p className="mt-1 whitespace-pre-wrap text-sm">{stage.success_criteria || t("unknown")}</p>
                          </div>
                        </div>
                        {stage.limitations.length ? (
                          <div>
                            <h5 className="font-medium text-sm">{t("limitationsTitle")}</h5>
                            <ul className="mt-1 list-disc pl-5 text-muted-foreground text-sm">
                              {stage.limitations.map((limitation) => (
                                <li key={`${stage.id}-limitation-${limitation}`}>{limitation}</li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                        {!readOnly ? (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            disabled={busy || !current || draftDirty}
                            onClick={() => onApplyStage(stage)}
                          >
                            {t("applyToPlan")}
                          </Button>
                        ) : null}
                      </AccordionContent>
                    </AccordionItem>
                  );
                })}
              </Accordion>
            </div>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

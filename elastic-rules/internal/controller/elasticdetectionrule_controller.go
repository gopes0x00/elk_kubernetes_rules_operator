/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	elasticdetectionrulesv1 "github.com/gopes0x00/elastic-rules-operator/api/v1"
	elasticapi "github.com/gopes0x00/elastic-rules-operator/internal/elastic_api"
)

const edrFinalizer = "elasticdetectionrule.gopes0x00.internal/finalizer"

// ElasticDetectionRuleReconciler reconciles a ElasticDetectionRule object
type ElasticDetectionRuleReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	ElasticURL      string
	ElasticUsername string
	ElasticPassword string
}

// +kubebuilder:rbac:groups=elasticdetectionrules.gopes0x00.internal,resources=elasticdetectionrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=elasticdetectionrules.gopes0x00.internal,resources=elasticdetectionrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=elasticdetectionrules.gopes0x00.internal,resources=elasticdetectionrules/finalizers,verbs=update

func (r *ElasticDetectionRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var edr elasticdetectionrulesv1.ElasticDetectionRule
	if err := r.Get(ctx, req.NamespacedName, &edr); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ElasticDetectionRule resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get ElasticDetectionRule")
		return ctrl.Result{}, err
	}

	var elk elasticapi.ElasticConnection
	elk.Url = r.ElasticURL
	elk.Username = r.ElasticUsername
	elk.Password = r.ElasticPassword

	// Handle deletion if object is marked for deletion
	if !edr.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&edr, edrFinalizer) {
			log.Info("Deleting rule from Elastic", "ruleID", edr.Status.RuleID)
			if edr.Status.RuleID != "" {
				if _, err := elk.DeleteRule(edr.Status.RuleID); err != nil {
					log.Error(err, "Failed to delete rule from Elastic", "ruleID", edr.Status.RuleID)
					return ctrl.Result{}, err
				}
			}

			controllerutil.RemoveFinalizer(&edr, edrFinalizer)
			if err := r.Update(ctx, &edr); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer for this CR set if not present
	if !controllerutil.ContainsFinalizer(&edr, edrFinalizer) {
		controllerutil.AddFinalizer(&edr, edrFinalizer)
		if err := r.Update(ctx, &edr); err != nil {
			return ctrl.Result{}, err
		}
	}

	// If RuleID is empty in status, create rule in Elastic
	if edr.Status.RuleID == "" {
		log.Info("Creating rule in Elastic", "name", edr.Spec.RuleName)
		ruleID, err := elk.CreateRule(edr)
		if err != nil {
			log.Error(err, "Failed to create rule in Elastic")
			return ctrl.Result{}, err
		}

		now := metav1.NewTime(time.Now())
		edr.Status.RuleID = ruleID
		edr.Status.LastUpdated = &now
		edr.Status.ObservedGeneration = edr.Generation

		if err := r.Status().Update(ctx, &edr); err != nil {
			log.Error(err, "Failed to update ElasticDetectionRule status after creation")
			return ctrl.Result{}, err
		}

		log.Info("Successfully created Elastic rule and updated CR status", "ruleID", ruleID)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Check if the rule exists in Elastic
	_, getErr := elk.ListRule(edr.Status.RuleID)
	if getErr != nil {
		log.Info("Rule not found in Elastic, recreating rule...", "ruleID", edr.Status.RuleID)
		ruleID, createErr := elk.CreateRule(edr)
		if createErr != nil {
			log.Error(createErr, "Failed to recreate rule in Elastic")
			return ctrl.Result{}, createErr
		}

		now := metav1.NewTime(time.Now())
		edr.Status.RuleID = ruleID
		edr.Status.LastUpdated = &now
		edr.Status.ObservedGeneration = edr.Generation
		if err := r.Status().Update(ctx, &edr); err != nil {
			log.Error(err, "Failed to update ElasticDetectionRule status after recreation")
			return ctrl.Result{}, err
		}

		log.Info("Successfully recreated missing Elastic rule", "ruleID", ruleID)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Rule exists in Elastic. Perform update if spec generation changed.
	if edr.Status.ObservedGeneration != edr.Generation {
		log.Info("Spec changed, updating existing rule in Elastic", "ruleID", edr.Status.RuleID)
		if err := elk.UpdateRule(edr); err != nil {
			log.Error(err, "Failed to update rule in Elastic", "ruleID", edr.Status.RuleID)
			return ctrl.Result{}, err
		}

		now := metav1.NewTime(time.Now())
		edr.Status.LastUpdated = &now
		edr.Status.ObservedGeneration = edr.Generation
		if err := r.Status().Update(ctx, &edr); err != nil {
			log.Error(err, "Failed to update ElasticDetectionRule status after update")
			return ctrl.Result{}, err
		}

		log.Info("Successfully updated Elastic rule and updated CR status", "ruleID", edr.Status.RuleID)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Rule exists and spec has not changed; requeue in 1 minute to check Elastic state periodically
	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticDetectionRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&elasticdetectionrulesv1.ElasticDetectionRule{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Named("elasticdetectionrule").
		Complete(r)
}

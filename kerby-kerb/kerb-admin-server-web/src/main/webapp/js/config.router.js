'use strict';

/**
 * Config for the router
 */
angular.module('app')
  .run(
    ['$rootScope', '$state', '$stateParams',
      function ($rootScope,   $state,   $stateParams) {
          $rootScope.$state = $state;
          $rootScope.$stateParams = $stateParams;        
      }
    ]
  )
  .config(
    ['$stateProvider', '$urlRouterProvider',
      function ($stateProvider,   $urlRouterProvider) {
          $urlRouterProvider
              .otherwise('/app/dashboard-v1');
          $stateProvider
              .state('app', {
                  abstract: true,
                  url: '/app',
                  templateUrl: 'tpl/app.html'
              })
              .state('app.dashboard-v1', {
                  url: '/dashboard-v1',
                  templateUrl: 'tpl/table_grid.html',
                  resolve: {
                      deps: ['$ocLazyLoad',
                        function( $ocLazyLoad ){
                          return $ocLazyLoad.load('ngGrid').then(
                              function(){
                                  return $ocLazyLoad.load('js/controllers/grid.js');
                              }
                          );
                      }]
                  }
              })
              // menu
              .state('app.menu', {
                  url: '/menu',
                  template: '<div ui-view></div>'
              })
              .state('app.menu.kadmin', {
                  url: '/grid',
                  templateUrl: 'tpl/table_grid.html',
                  resolve: {
                      deps: ['$ocLazyLoad',
                        function( $ocLazyLoad ){
                          return $ocLazyLoad.load('ngGrid').then(
                              function(){
                                  return $ocLazyLoad.load('js/controllers/grid.js');
                              }
                          );
                      }]
                  }
              })
      }
    ]
  );
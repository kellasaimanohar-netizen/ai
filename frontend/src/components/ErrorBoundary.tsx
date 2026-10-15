import React from 'react';
import { Alert, Button } from './ui';

/** Keeps one broken page from blanking the whole app: shows the error and lets the user retry. */
export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('Page crashed:', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Alert
        tone="critical"
        title="This page hit an error"
        action={<Button size="sm" onClick={() => this.setState({ error: null })}>Try again</Button>}
      >
        {this.state.error.message}
      </Alert>
    );
  }
}
